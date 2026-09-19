#!/usr/bin/env python3
"""
DiskImageWalker
================
أداة أمن سيبراني (Digital Forensics) لتحليل صور أقراص FAT32 واسترجاع
الملفات منها - تعمل بـ Python القياسية فقط (بدون Third-party Libraries).

الاستخدام السريع:
    python diskimagewalker.py --help
    python diskimagewalker.py info   disk.img
    python diskimagewalker.py list   disk.img --all
    python diskimagewalker.py hexdump disk.img --offset 0 --length 512
    python diskimagewalker.py carve  disk.img --types jpg,png
"""

import argparse
import json
import logging
import os
import struct
import sys

__version__ = "1.0.0"

logger = logging.getLogger("diskimagewalker")


# ============================================================
# استثناءات مخصصة للأداة
# ============================================================
class DiskImageWalkerError(Exception):
    """خطأ عام متوقع في الأداة (نعرضه للمستخدم برسالة واضحة بدل Traceback)."""


class InvalidImageError(DiskImageWalkerError):
    """صورة القرص غير صالحة أو تالفة أو المعاملات المعطاة غير صحيحة."""


class ConfigError(DiskImageWalkerError):
    """مشكلة في ملف الإعدادات (--config)."""


# ============================================================
# الإعدادات (--config)
# ============================================================
DEFAULT_CONFIG = {
    "partition_start_sector": 2048,
    "output_dir": "carved_output",
}


def load_config(config_path):
    """يحمّل ملف إعدادات JSON اختياري ويدمجه مع القيم الافتراضية."""
    if config_path is None:
        return dict(DEFAULT_CONFIG)

    if not os.path.exists(config_path):
        raise ConfigError(f"ملف الإعدادات غير موجود: {config_path}")

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            user_cfg = json.load(f)
    except json.JSONDecodeError as e:
        raise ConfigError(f"ملف الإعدادات تالف (JSON غير صالح): {e}")
    except UnicodeDecodeError:
        raise ConfigError(f"ملف الإعدادات تالف (ترميز غير صالح): {config_path}")
    except PermissionError:
        raise ConfigError(f"لا توجد صلاحية كافية لقراءة ملف الإعدادات: {config_path}")

    if not isinstance(user_cfg, dict):
        raise ConfigError("ملف الإعدادات يجب أن يكون كائن JSON (object) في المستوى الأعلى")

    cfg = dict(DEFAULT_CONFIG)
    cfg.update(user_cfg)
    return cfg


# ============================================================
# FAT32: Boot Sector + متابعة سلسلة FAT الكاملة
# ============================================================
def read_boot_sector(image_path, partition_start_sector):
    boot_offset = partition_start_sector * 512
    with open(image_path, "rb") as f:
        f.seek(boot_offset)
        boot_data = f.read(512)

    if len(boot_data) < 512:
        raise InvalidImageError(
            "الملف أصغر من أن يحتوي Boot Sector صالح عند هذا الموقع - "
            "تأكد من صحة --partition-start"
        )

    if boot_data[510:512] != b"\x55\xAA":
        raise InvalidImageError(
            "توقيع Boot Sector (55AA) غير موجود عند القطاع "
            f"{partition_start_sector} - جرّب رقم قطاع آخر عبر --partition-start"
        )

    params = {
        "bytes_per_sector": struct.unpack_from("<H", boot_data, 0x0B)[0],
        "sectors_per_cluster": boot_data[0x0D],
        "reserved_sectors": struct.unpack_from("<H", boot_data, 0x0E)[0],
        "num_fats": boot_data[0x10],
        "sectors_per_fat": struct.unpack_from("<I", boot_data, 0x24)[0],
        "root_cluster": struct.unpack_from("<I", boot_data, 0x2C)[0],
        "partition_start_sector": partition_start_sector,
    }

    if params["bytes_per_sector"] == 0 or params["sectors_per_cluster"] == 0:
        raise InvalidImageError("قيم Boot Sector غير منطقية - الصورة قد تكون تالفة أو ليست FAT32")

    params["fat_start_sector"] = params["reserved_sectors"]
    params["data_start_sector"] = params["reserved_sectors"] + (
        params["num_fats"] * params["sectors_per_fat"]
    )
    return params


def read_fat_table(image_path, params):
    offset = (params["partition_start_sector"] + params["fat_start_sector"]) * params["bytes_per_sector"]
    size = params["sectors_per_fat"] * params["bytes_per_sector"]
    with open(image_path, "rb") as f:
        f.seek(offset)
        data = f.read(size)
    if len(data) < size:
        raise InvalidImageError("تعذّرت قراءة جدول FAT كاملاً - الملف قد يكون مقطوعاً")
    return data


def get_next_cluster(fat_data, cluster):
    offset = cluster * 4
    if offset + 4 > len(fat_data):
        return 0x0FFFFFFF
    val = struct.unpack_from("<I", fat_data, offset)[0]
    return val & 0x0FFFFFFF


def get_cluster_chain(fat_data, start_cluster):
    """يتابع سلسلة الـ Clusters كاملة حتى نهايتها (EOC)."""
    FAT32_EOC_MIN = 0x0FFFFFF8
    chain = []
    cluster = start_cluster
    visited = set()
    while cluster >= 2 and cluster not in visited:
        visited.add(cluster)
        chain.append(cluster)
        cluster = get_next_cluster(fat_data, cluster)
        if cluster >= FAT32_EOC_MIN or cluster == 0x0FFFFFF7:
            break
    return chain


def cluster_to_sector(cluster, params):
    return params["data_start_sector"] + (cluster - 2) * params["sectors_per_cluster"]


def read_cluster_chain_data(image_path, params, fat_data, start_cluster):
    chain = get_cluster_chain(fat_data, start_cluster)
    if not chain:
        raise InvalidImageError(f"سلسلة Clusters غير صالحة بدءاً من الكتلة {start_cluster}")

    cluster_size = params["sectors_per_cluster"] * params["bytes_per_sector"]
    all_data = bytearray()
    with open(image_path, "rb") as f:
        for cluster in chain:
            sector = params["partition_start_sector"] + cluster_to_sector(cluster, params)
            f.seek(sector * params["bytes_per_sector"])
            all_data += f.read(cluster_size)
    return bytes(all_data), chain


# ============================================================
# تحليل مدخلات الدليل (Directory Entries) - يدعم LFN والحذف
# ============================================================
def parse_directory_entries(dir_data):
    entries = []
    lfn_parts = []
    i = 0
    while i < len(dir_data):
        entry = dir_data[i:i + 32]
        if len(entry) < 32:
            break

        first_byte = entry[0]
        if first_byte == 0x00:
            break

        attributes = entry[11]

        # مدخل اسم طويل (LFN)
        if attributes == 0x0F:
            seq = entry[0]
            order = seq & 0x1F
            name_bytes = entry[1:11] + entry[14:26] + entry[28:32]
            try:
                part = name_bytes.decode("utf-16-le", errors="ignore")
            except Exception:
                part = ""
            part = part.split("\x00")[0]
            lfn_parts.append((order, part))
            i += 32
            continue

        name_part = entry[0:8]
        ext_part = entry[8:11]
        is_deleted = first_byte == 0xE5

        # 0x05 بديل عن 0xE5 (KANJI escape) - ليس حذفاً فعلياً
        if first_byte == 0x05:
            name_part = bytes([0xE5]) + name_part[1:]
            is_deleted = False
        elif is_deleted:
            # الحرف الأول الحقيقي فُقد نهائياً عند الحذف (استُبدل بـ 0xE5) -
            # نعوّضه برمز "؟" ليكون واضحاً أنه غير قابل للاسترجاع، بدل حذفه بصمت
            name_part = b"?" + name_part[1:]

        name_str = name_part.decode("ascii", errors="ignore").strip()
        ext_str = ext_part.decode("ascii", errors="ignore").strip()
        is_volume_label = bool(attributes & 0x08) and not bool(attributes & 0x10)

        if not is_volume_label and (name_str or ext_str):
            short_name = f"{name_str}.{ext_str}" if ext_str else name_str
            long_name = None
            if lfn_parts:
                lfn_parts.sort(key=lambda x: x[0] & 0x1F)
                long_name = "".join(p for _, p in lfn_parts)
            full_name = long_name if long_name else short_name

            size = struct.unpack_from("<I", entry, 28)[0]
            first_cluster_hi = struct.unpack_from("<H", entry, 20)[0]
            first_cluster_lo = struct.unpack_from("<H", entry, 26)[0]
            first_cluster = (first_cluster_hi << 16) | first_cluster_lo

            entries.append({
                "name": full_name,
                "short_name": short_name,
                "attributes": attributes,
                "is_deleted": is_deleted,
                "is_dir": bool(attributes & 0x10),
                "size": size,
                "first_cluster": first_cluster,
            })

        lfn_parts = []
        i += 32

    return entries


# ============================================================
# Hex Viewer
# ============================================================
def hex_dump(image_path, offset=0, length=512):
    with open(image_path, "rb") as f:
        f.seek(offset)
        data = f.read(length)

    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"  {offset + i:08X}  {hex_part:<48}  {ascii_part}")
    return "\n".join(lines), len(data)


# ============================================================
# Carving (استخراج بالتواقيع)
# ============================================================
CARVE_SIGNATURES = {
    "jpg": {"header": b"\xFF\xD8\xFF\xE0", "footer": b"\xFF\xD9"},
    "png": {"header": b"\x89PNG\r\n\x1a\n", "footer": b"\x49\x45\x4E\x44\xAE\x42\x60\x82"},
}


def carve_files(image_path, output_dir, file_types=None):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    with open(image_path, "rb") as f:
        data = f.read()

    types_to_scan = file_types if file_types else list(CARVE_SIGNATURES.keys())
    results = []
    file_counter = 1

    for file_type in types_to_scan:
        file_type = file_type.strip().lower()
        if file_type not in CARVE_SIGNATURES:
            logger.warning("نوع ملف غير مدعوم للاستخراج: %s - تم تجاهله", file_type)
            continue

        sig = CARVE_SIGNATURES[file_type]
        header, footer = sig["header"], sig["footer"]
        start_pos = 0

        while True:
            start_pos = data.find(header, start_pos)
            if start_pos == -1:
                break

            # نحصر البحث عن الـ footer قبل بداية التوقيع التالي (يتجنب قطع الملف
            # عند وجود thumbnail بنفس التوقيع داخل EXIF) ونأخذ آخر تطابق ضمن هذا المدى
            next_header = data.find(header, start_pos + len(header))
            search_end = next_header if next_header != -1 else len(data)

            end_pos = data.rfind(footer, start_pos + len(header), search_end)
            if end_pos == -1:
                end_pos = data.find(footer, start_pos + len(header))
                if end_pos == -1:
                    end_pos = len(data) - len(footer)

            carved_data = data[start_pos:end_pos + len(footer)]
            output_file = os.path.join(output_dir, f"carved_{file_counter}.{file_type}")
            with open(output_file, "wb") as out_f:
                out_f.write(carved_data)

            results.append((output_file, start_pos, end_pos + len(footer)))
            file_counter += 1
            start_pos = end_pos + len(footer)

    return results


# ============================================================
# أوامر CLI (Subcommands)
# ============================================================
def cmd_info(args, config):
    params = read_boot_sector(args.image, args.partition_start)
    print("--- معلومات Boot Sector (FAT32) ---")
    print(f"  البايت لكل قطاع:        {params['bytes_per_sector']}")
    print(f"  القطاعات لكل كتلة:       {params['sectors_per_cluster']}")
    print(f"  حجم الكتلة:              {params['bytes_per_sector'] * params['sectors_per_cluster']} بايت")
    print(f"  القطاعات المحجوزة:       {params['reserved_sectors']}")
    print(f"  عدد جداول FAT:           {params['num_fats']}")
    print(f"  القطاعات لكل جدول FAT:   {params['sectors_per_fat']}")
    print(f"  كتلة بداية الجذر:        {params['root_cluster']}")
    print(f"  بداية منطقة البيانات:    القطاع {params['data_start_sector']}")


def cmd_list(args, config):
    params = read_boot_sector(args.image, args.partition_start)
    fat_data = read_fat_table(args.image, params)
    dir_data, chain = read_cluster_chain_data(args.image, params, fat_data, params["root_cluster"])
    entries = parse_directory_entries(dir_data)

    active = [e for e in entries if not e["is_deleted"]]
    deleted = [e for e in entries if e["is_deleted"]]

    logger.debug("سلسلة Clusters لمجلد الجذر: %s", chain)

    print("--- الملفات والمجلدات في الجذر ---")
    if active:
        print("\nموجودة حالياً:")
        for e in active:
            kind = "مجلد" if e["is_dir"] else "ملف"
            print(f"  [+] {e['name']}  ({kind}, {e['size']} بايت, cluster={e['first_cluster']})")
    else:
        print("\nلا توجد ملفات موجودة حالياً في الجذر.")

    if args.deleted or args.all:
        if deleted:
            print("\nمحذوفة (قابلة للاسترجاع المحتمل):")
            for e in deleted:
                kind = "مجلد" if e["is_dir"] else "ملف"
                print(f"  [x] {e['name']}  ({kind}, {e['size']} بايت, cluster={e['first_cluster']})")
        else:
            print("\nلا توجد ملفات محذوفة في الجذر.")


def cmd_hexdump(args, config):
    text, read_len = hex_dump(args.image, offset=args.offset, length=args.length)
    print(f"تم قراءة {read_len} بايت بدءاً من الإزاحة {args.offset}")
    print()
    print(text)


def cmd_carve(args, config):
    output_dir = args.output or config.get("output_dir", "carved_output")
    types = args.types.split(",") if args.types else None
    results = carve_files(args.image, output_dir, types)

    if not results:
        print("لم يتم العثور على أي ملفات مطابقة للتواقيع المعروفة.")
        return

    print(f"--- تم استخراج {len(results)} ملف/ملفات إلى: {output_dir} ---")
    for path, start, end in results:
        print(f"  [+] {path}   (الموقع: {start} - {end})")


# ============================================================
# بناء الـ Parser الرئيسي
# ============================================================
def build_parser():
    # خيارات عامة (--config و --log-level) نعرّفها في parent مشترك حتى تُقبل
    # سواء كُتبت قبل اسم الأمر الفرعي أو بعده، مثال:
    #   diskimagewalker.py --log-level DEBUG info disk.img
    #   diskimagewalker.py info disk.img --log-level DEBUG
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", metavar="PATH", default=None, help="مسار ملف إعدادات JSON اختياري")
    common.add_argument(
        "--log-level",
        default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="مستوى تفاصيل السجلّ (افتراضي: WARNING)",
    )

    parser = argparse.ArgumentParser(
        prog="diskimagewalker",
        description="DiskImageWalker - أداة تحليل واسترجاع بيانات من صور أقراص FAT32 (Digital Forensics)",
        parents=[common],
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    p_info = subparsers.add_parser("info", help="عرض معلومات Boot Sector", parents=[common])
    p_info.add_argument("image", help="مسار صورة القرص")
    p_info.add_argument("--partition-start", type=int, default=2048,
                         help="رقم القطاع لبداية القسم (افتراضي: 2048)")
    p_info.set_defaults(func=cmd_info)

    p_list = subparsers.add_parser("list", help="عرض ملفات المجلد الجذري", parents=[common])
    p_list.add_argument("image", help="مسار صورة القرص")
    p_list.add_argument("--partition-start", type=int, default=2048,
                         help="رقم القطاع لبداية القسم (افتراضي: 2048)")
    p_list.add_argument("--deleted", action="store_true", help="عرض الملفات المحذوفة أيضاً")
    p_list.add_argument("--all", action="store_true", help="عرض الملفات الموجودة والمحذوفة معاً")
    p_list.set_defaults(func=cmd_list)

    p_hex = subparsers.add_parser("hexdump", help="عرض بيانات ثنائية بصيغة Hex + ASCII", parents=[common])
    p_hex.add_argument("image", help="مسار صورة القرص")
    p_hex.add_argument("--offset", type=int, default=0, help="موقع البداية بالبايت (افتراضي: 0)")
    p_hex.add_argument("--length", type=int, default=512, help="عدد البايتات المراد عرضها (افتراضي: 512)")
    p_hex.set_defaults(func=cmd_hexdump)

    p_carve = subparsers.add_parser("carve", help="استخراج ملفات مدفونة بالتواقيع (JPEG/PNG)", parents=[common])
    p_carve.add_argument("image", help="مسار صورة القرص")
    p_carve.add_argument("--output", help="مجلد الإخراج (افتراضي من الإعدادات أو carved_output)")
    p_carve.add_argument("--types", help="أنواع الملفات مفصولة بفواصل، مثال: jpg,png")
    p_carve.set_defaults(func=cmd_carve)

    return parser


# ============================================================
# نقطة الدخول الرئيسية (كل الأخطاء المتوقعة تُمسك هنا)
# ============================================================
def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(level=getattr(logging, args.log_level), format="%(levelname)s: %(message)s")

    try:
        config = load_config(args.config)
    except ConfigError as e:
        print(f"[خطأ في الإعدادات] {e}", file=sys.stderr)
        return 1

    if not os.path.exists(args.image):
        print(f"[خطأ] الملف غير موجود: {args.image}", file=sys.stderr)
        return 1

    try:
        with open(args.image, "rb"):
            pass
    except PermissionError:
        print(f"[خطأ] لا توجد صلاحية كافية للوصول إلى: {args.image}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"[خطأ] تعذّر فتح الملف: {e}", file=sys.stderr)
        return 1

    try:
        args.func(args, config)
    except InvalidImageError as e:
        print(f"[خطأ] صورة القرص غير صالحة: {e}", file=sys.stderr)
        return 1
    except FileNotFoundError as e:
        print(f"[خطأ] ملف غير موجود: {e}", file=sys.stderr)
        return 1
    except PermissionError as e:
        print(f"[خطأ] صلاحيات غير كافية: {e}", file=sys.stderr)
        return 1
    except struct.error as e:
        print(f"[خطأ] بيانات ثنائية غير متوقعة أثناء التحليل: {e}", file=sys.stderr)
        return 1
    except DiskImageWalkerError as e:
        print(f"[خطأ] {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[تنبيه] تم إيقاف العملية من قبل المستخدم.", file=sys.stderr)
        return 130
    except Exception as e:
        logger.debug("تفاصيل الخطأ الكاملة:", exc_info=True)
        print(f"[خطأ غير متوقع] {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())


