const { Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
        AlignmentType, HeadingLevel, LevelFormat, BorderStyle, WidthType,
        ShadingType, PageBreak } = require('docx');
const fs = require('fs');

const PAGE_WIDTH = 12240;  // US Letter width in DXA
const PAGE_HEIGHT = 15840; // US Letter height in DXA
const MARGIN = 1440;       // 1 inch margins
const CONTENT_WIDTH = PAGE_WIDTH - 2 * MARGIN; // 9360 DXA

const border = { style: BorderStyle.SINGLE, size: 1, color: "666666" };
const borders = { top: border, bottom: border, left: border, right: border };
const cellMargins = { top: 80, bottom: 80, left: 120, right: 120 };

function heading1(text) {
    return new Paragraph({
        heading: HeadingLevel.HEADING_1,
        spacing: { before: 360, after: 180 },
        children: [new TextRun({ text, bold: true, font: "Arial", size: 32, color: "1F4E79" })]
    });
}

function heading2(text) {
    return new Paragraph({
        heading: HeadingLevel.HEADING_2,
        spacing: { before: 280, after: 140 },
        children: [new TextRun({ text, bold: true, font: "Arial", size: 28, color: "2E75B6" })]
    });
}

function heading3(text) {
    return new Paragraph({
        heading: HeadingLevel.HEADING_3,
        spacing: { before: 200, after: 100 },
        children: [new TextRun({ text, bold: true, font: "Arial", size: 24, color: "3D85C6" })]
    });
}

function para(text, opts = {}) {
    return new Paragraph({
        spacing: { before: 120, after: 120 },
        children: [new TextRun({ text, font: "Arial", size: 22, ...opts })]
    });
}

function bullet(text, level = 0) {
    return new Paragraph({
        numbering: { reference: "bullets", level },
        spacing: { before: 60, after: 60 },
        children: [new TextRun({ text, font: "Arial", size: 22 })]
    });
}

function codeBlock(text) {
    return new Paragraph({
        spacing: { before: 120, after: 120 },
        indent: { left: 360 },
        children: [new TextRun({ text, font: "Consolas", size: 18, color: "333333" })]
    });
}

function makeTable(headers, rows, widths) {
    const headerCells = headers.map((h, i) =>
        new TableCell({
            borders,
            width: { size: widths[i], type: WidthType.DXA },
            shading: { fill: "D5E8F0", type: ShadingType.CLEAR },
            margins: cellMargins,
            children: [new Paragraph({
                children: [new TextRun({ text: h, bold: true, font: "Arial", size: 20 })]
            })]
        })
    );

    const dataRows = rows.map(row =>
        new TableRow({
            children: row.map((cell, i) =>
                new TableCell({
                    borders,
                    width: { size: widths[i], type: WidthType.DXA },
                    margins: cellMargins,
                    children: [new Paragraph({
                        children: [new TextRun({ text: String(cell), font: "Arial", size: 20 })]
                    })]
                })
            )
        })
    );

    return new Table({
        width: { size: CONTENT_WIDTH, type: WidthType.DXA },
        columnWidths: widths,
        rows: [new TableRow({ children: headerCells }), ...dataRows]
    });
}

const doc = new Document({
    numbering: {
        config: [
            { reference: "bullets", levels: [{ level: 0, format: LevelFormat.BULLET, text: "\u2022", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
            { reference: "numbers", levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
        ]
    },
    styles: {
        default: { document: { run: { font: "Arial", size: 22 } } },
        paragraphStyles: [
            { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
              run: { size: 32, bold: true, font: "Arial", color: "1F4E79" },
              paragraph: { spacing: { before: 360, after: 180 }, outlineLevel: 0 } },
            { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
              run: { size: 28, bold: true, font: "Arial", color: "2E75B6" },
              paragraph: { spacing: { before: 280, after: 140 }, outlineLevel: 1 } },
            { id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true,
              run: { size: 24, bold: true, font: "Arial", color: "3D85C6" },
              paragraph: { spacing: { before: 200, after: 100 }, outlineLevel: 2 } },
        ]
    },
    sections: [{
        properties: {
            page: {
                size: { width: PAGE_WIDTH, height: PAGE_HEIGHT },
                margin: { top: MARGIN, right: MARGIN, bottom: MARGIN, left: MARGIN }
            }
        },
        children: [
            // Title
            new Paragraph({
                alignment: AlignmentType.CENTER,
                spacing: { before: 480, after: 240 },
                children: [new TextRun({ text: "RISC-V 安全启动镜像验签设计文档", bold: true, font: "Arial", size: 44, color: "1F4E79" })]
            }),
            new Paragraph({
                alignment: AlignmentType.CENTER,
                spacing: { before: 0, after: 480 },
                children: [new TextRun({ text: "基于 K 扩展 (SHA) 和向量扩展 (ECDSA P-256)", font: "Arial", size: 26, color: "666666" })]
            }),
            new Paragraph({
                alignment: AlignmentType.CENTER,
                spacing: { before: 0, after: 720 },
                children: [new TextRun({ text: "版本 1.0  |  2026-04-08", font: "Arial", size: 22, color: "888888" })]
            }),

            // 1. 概述
            heading1("1. 概述"),
            para("本文档描述了一个基于 RISC-V 架构的安全启动镜像验签库的详细设计方案。该库支持 ECDSA P-256/P-384 签名验证，使用 RISC-V K 扩展加速 SHA 哈希运算，使用 RISC-V 向量扩展 (RVV) 加速 ECDSA 点乘运算。"),
            para(""),
            heading2("1.1 主要特性"),
            bullet("ECDSA P-256 签名验证 - 使用 RVV 向量扩展加速"),
            bullet("ECDSA P-384 签名验证 - 通过 mbedTLS 实现"),
            bullet("SHA-256/SHA-384 哈希 - 使用 K 扩展 intrinsics 加速"),
            bullet("固定 P-256 曲线参数 - 编译时 baked in，减少运行时开销"),
            bullet("常数时间运算 - 使用 B 扩展 cmix/cmov 抗时序攻击"),
            bullet("模块化架构 - 分离的哈希、ECDSA 和验签模块"),
            bullet("嵌入式公钥 - 用于验签的静态 ECDSA 公钥"),

            new Paragraph({ children: [new PageBreak()] }),

            // 2. 系统架构
            heading1("2. 系统架构"),
            heading2("2.1 整体架构"),
            para("安全启动验签库采用模块化设计，主要包含以下组件："),
            para(""),
            makeTable(
                ["组件", "说明"],
                [
                    ["hash 模块", "SHA-256/SHA-384 哈希计算 (K 扩展加速)"],
                    ["ecdsa 模块", "ECDSA 签名验证 (RVV 加速 P-256)"],
                    ["verify 模块", "镜像验签入口点"],
                    ["image_tool", "签名镜像打包工具"],
                ],
                [3000, 6360]
            ),
            para(""),
            heading2("2.2 目录结构"),
            codeBlock("secure_boot/"),
            codeBlock("├── include/               # 头文件"),
            codeBlock("│   ├── image_header.h    # 镜像头结构"),
            codeBlock("│   ├── hash.h              # 哈希接口"),
            codeBlock("│   ├── ecdsa.h             # ECDSA 接口"),
            codeBlock("│   └── verify.h            # 验签接口"),
            codeBlock("├── src/                   # 源代码"),
            codeBlock("│   ├── hash.c              # 哈希实现 (K 扩展)"),
            codeBlock("│   ├── ecdsa.c             # ECDSA 实现 (RVV)"),
            codeBlock("│   ├── verify.c            # 验签逻辑"),
            codeBlock("│   └── image_tool.c        # 镜像签名工具"),
            codeBlock("├── keys/                   # 公钥"),
            codeBlock("│   ├── ecdsa_pubkey.h"),
            codeBlock("│   └── ecdsa_pubkey.c"),
            codeBlock("├── thirdparty/"),
            codeBlock("│   ├── riscv-crypto/       # K 扩展 intrinsics"),
            codeBlock("│   └── mbedtls/            # ECDSA 库"),
            codeBlock("└── Makefile"),

            new Paragraph({ children: [new PageBreak()] }),

            // 3. 硬件加速
            heading1("3. 硬件加速设计"),
            heading2("3.1 RISC-V 扩展组成"),
            makeTable(
                ["扩展", "组成", "提供的功能"],
                [
                    ["K (Zk)", "Zkn + Zkr + Zkt", "SHA-256/512、AES、SM3/SM4"],
                    ["Zkn", "Zknd + Zkne + Zknh + Zbkb + Zbkc + Zbkx", "AES + SHA-2 + 位操作"],
                    ["Zkr", "-", "熵源 (TRNG)"],
                    ["Zkt", "-", "数据无关执行延迟 (常数时间)"],
                    ["V (RVV)", "-", "向量运算 (ECDSA 点乘辅助)"],
                ],
                [1800, 3600, 3960]
            ),
            para(""),
            heading2("3.2 K 扩展加速 (SHA 哈希)"),
            para("K 扩展提供了 SHA-256 和 SHA-512 的专用指令，可大幅加速哈希运算："),
            para(""),
            makeTable(
                ["算法", "指令", "功能"],
                [
                    ["SHA-256", "_sha256sig0", "σigma0: ROTR(x,7) ^ ROTR(x,18) ^ SHR(x,3)"],
                    ["SHA-256", "_sha256sig1", "σigma1: ROTR(x,17) ^ ROTR(x,19) ^ SHR(x,10)"],
                    ["SHA-256", "_sha256sum0", "Σigma0: ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22)"],
                    ["SHA-256", "_sha256sum1", "Σigma1: ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25)"],
                    ["SHA-512", "_sha512sig0", "σigma0: ROTR(x,1) ^ ROTR(x,8) ^ SHR(x,7)"],
                    ["SHA-512", "_sha512sig1", "σigma1: ROTR(x,19) ^ ROTR(x,61) ^ SHR(x,6)"],
                    ["SHA-512", "_sha512sum0", "Σigma0: ROTR(x,28) ^ ROTR(x,34) ^ ROTR(x,39)"],
                    ["SHA-512", "_sha512sum1", "Σigma1: ROTR(x,14) ^ ROTR(x,18) ^ ROTR(x,41)"],
                ],
                [1500, 2000, 5860]
            ),
            para(""),
            heading2("3.3 RVV 加速 (ECDSA 点乘)"),
            para("RISC-V 向量扩展用于加速 ECDSA P-256 验签中的点乘运算："),
            para(""),
            makeTable(
                ["操作", "RVV 加速方式"],
                [
                    ["4× uint64_t 加载/存储", "vlseg4e64.v / vsseg4e64.v (单指令完成)"],
                    ["模块化加/减", "向量并行 limb 操作"],
                    ["模块化约简", "向量移位操作 (P-256 素数特殊形式)"],
                    ["模块化乘法", "标量 MUL (RVV 无模块化乘法指令)"],
                ],
                [3000, 6360]
            ),
            para(""),
            para("注意：RISC-V 没有任何扩展提供 EC 点乘专用指令。完整的 ECDSA 验签使用软件实现，RVV 仅辅助加速大整数 limb 并行操作。"),

            new Paragraph({ children: [new PageBreak()] }),

            // 4. 算法原理
            heading1("4. 算法原理"),
            heading2("4.1 镜像格式"),
            para("安全启动镜像的格式如下："),
            para(""),
            codeBlock("[Header (32 bytes)][Image Data][Signature (64 or 96 bytes)]"),
            para(""),
            heading3("4.1.1 头结构 (32 字节)"),
            makeTable(
                ["偏移", "大小", "字段", "说明"],
                [
                    ["0", "4", "version", "镜像版本 (如 0x00010000 = 1.0.0)"],
                    ["4", "4", "image_type", "镜像类型标识符"],
                    ["8", "4", "image_length", "镜像数据长度 (字节)"],
                    ["12", "4", "flags", "标志位"],
                    ["16", "8", "timestamp", "构建时间戳"],
                    ["24", "4", "hash_algo", "哈希算法 (0=SHA256, 1=SHA384)"],
                    ["28", "4", "sig_algo", "签名算法 (0=P-256, 1=P-384)"],
                ],
                [1200, 1200, 2000, 3960]
            ),
            para(""),
            heading2("4.2 ECDSA 验签算法"),
            heading3("4.2.1 数学背景"),
            para("ECDSA (椭圆曲线数字签名算法) 基于椭圆曲线密码学。P-256 曲线定义如下："),
            para(""),
            codeBlock("y² = x³ + ax + b (mod p)"),
            para("其中："),
            bullet("p = 2^256 - 2^224 + 2^192 + 2^96 - 1 (P-256 素数)"),
            bullet("a = -3 (mod p)"),
            bullet("b = 0xE8B5B10C6B68EF3EF20E9DAB4B4050A85"),
            bullet("n = 0xFC632551F3B9CAC2A7179E84FFFFFFFF (曲线阶数)"),
            bullet("G = (Gx, Gy) (生成元/基点)"),
            para(""),
            heading3("4.2.2 验签流程"),
            para("给定公钥 Q、签名 (r, s) 和哈希值 e，验签步骤如下："),
            para(""),
            new Paragraph({ numbering: { reference: "numbers", level: 0 }, spacing: { before: 60, after: 60 },
                children: [new TextRun({ text: "验证 r, s ∈ [1, n-1]", font: "Arial", size: 22 })] }),
            new Paragraph({ numbering: { reference: "numbers", level: 0 }, spacing: { before: 60, after: 60 },
                children: [new TextRun({ text: "计算 w = s^(-1) mod n", font: "Arial", size: 22 })] }),
            new Paragraph({ numbering: { reference: "numbers", level: 0 }, spacing: { before: 60, after: 60 },
                children: [new TextRun({ text: "计算 u1 = e × w mod n", font: "Arial", size: 22 })] }),
            new Paragraph({ numbering: { reference: "numbers", level: 0 }, spacing: { before: 60, after: 60 },
                children: [new TextRun({ text: "计算 u2 = r × w mod n", font: "Arial", size: 22 })] }),
            new Paragraph({ numbering: { reference: "numbers", level: 0 }, spacing: { before: 60, after: 60 },
                children: [new TextRun({ text: "计算 R = u1×G + u2×Q", font: "Arial", size: 22 })] }),
            new Paragraph({ numbering: { reference: "numbers", level: 0 }, spacing: { before: 60, after: 60 },
                children: [new TextRun({ text: "验证 R.x mod n == r", font: "Arial", size: 22 })] }),
            para(""),

            new Paragraph({ children: [new PageBreak()] }),

            heading2("4.3 Montgomery Ladder (常数时间标量乘法)"),
            para("标量乘法 R = k×P 使用 Montgomery Ladder 算法实现常数时间执行："),
            para(""),
            codeBlock("R0 = O      // 无穷远点"),
            codeBlock("R1 = P"),
            codeBlock("for i from m-1 downto 0:"),
            codeBlock("    R0, R1 = cswap(R0, R1, k_i)   // 根据比特选择"),
            codeBlock("    T = R0 + R1                  // 点加"),
            codeBlock("    R0 = 2*R0                      // 点加倍"),
            codeBlock("    R1 = T"),
            codeBlock("    R0, R1 = cswap(R0, R1, k_i)   // 恢复"),
            para(""),
            para("关键特性："),
            bullet("每比特迭代执行一次点加和一次点加倍"),
            bullet("使用 cswap (常数时间选择) 根据比特值选择结果"),
            bullet("无分支依赖，抗时序攻击"),
            bullet("恒定的时钟周期数"),

            heading2("4.4 Jacobian 坐标与点运算"),
            para("Jacobian 坐标使用 (X, Y, Z) 表示点，满足仿射坐标关系："),
            para(""),
            codeBlock("x = X / Z²  (mod p)"),
            codeBlock("y = Y / Z³  (mod p)"),
            para(""),
            para("优势："),
            bullet("点加和点加倍无需模逆运算（最耗时的操作）"),
            bullet("仅在最终转换回仿射坐标时需要一次模逆"),
            bullet("a = -3 优化的点加倍公式：4M + 4S + 1add"),

            heading2("4.5 P-256 素数快速约简"),
            para("P-256 素数 p = 2^256 - 2^224 + 2^192 + 2^96 - 1 具有特殊形式，可加速约简："),
            para(""),
            codeBlock("2^256 ≡ 2^224 - 2^192 - 2^96 + 1  (mod p)"),
            para(""),
            para("这允许 512 位 → 256 位约简仅需 2 次迭代，无需除法运算。"),

            new Paragraph({ children: [new PageBreak()] }),

            // 5. 设计实现
            heading1("5. 设计与实现细节"),
            heading2("5.1 固定 P-256 曲线参数"),
            para("所有 P-256 常量作为 static const 编译时 baked in："),
            para(""),
            makeTable(
                ["参数", "值", "用途"],
                [
                    ["P256_P", "2^256 - 2^224 + 2^192 + 2^96 - 1", "素数模 p"],
                    ["P256_N", "0xFC632551...", "曲线阶数 (点的个数)"],
                    ["P256_A", "-3 mod p", "曲线系数 a = -3"],
                    ["P256_B", "0xE8B5B10C...", "曲线系数 b"],
                    ["P256_GX/GY", "基点坐标", "生成元 G"],
                ],
                [1800, 3000, 4560]
            ),
            para(""),
            para("优势："),
            bullet("消除运行时常数加载开销"),
            bullet("消除表查找"),
            bullet("减少分支"),

            heading2("5.2 常数时间运算 (B 扩展)"),
            para("使用 RISC-V B 扩展的 cmix 指令实现常数时间操作："),
            para(""),
            codeBlock("// 常数时间条件选择 (cmix)"),
            codeBlock("ct_select(sel, if_true, if_false)  // sel=1 返回 if_true，否则返回 if_false"),
            para(""),
            codeBlock("// 常数时间零值检测"),
            codeBlock("ct_is_zero(x)  // x==0 返回 1，否则返回 0"),
            para(""),
            heading2("5.3 大整数运算 (4× uint64_t)"),
            makeTable(
                ["函数", "说明"],
                [
                    ["p256_add_full()", "256 位加法，返回进位"],
                    ["p256_sub_full()", "256 位减法，返回借位"],
                    ["p256_mod_add()", "模 p 加法 (常数时间)"],
                    ["p256_mod_sub()", "模 p 减法 (常数时间)"],
                    ["p256_mul()", "256×256→512 位乘法 (schoolbook)"],
                    ["p256_mod_reduce()", "512→256 位模 p 约简 (2 次迭代)"],
                    ["p256_mod_mul()", "模 p 乘法 (mul + reduce)"],
                    ["p256_mod_inv()", "模 p 逆元 (固定窗口指数运算)"],
                ],
                [3500, 5860]
            ),

            new Paragraph({ children: [new PageBreak()] }),

            heading2("5.4 ECDSA 验签实现"),
            para("完整 ECDSA P-256 验签流程："),
            para(""),
            codeBlock("int ecdsa_verify(pubkey, pubkey_len, algo, hash, hash_len, signature, sig_len) {"),
            codeBlock("    // 1. 解析 r, s (大端 → 小端 uint64_t)"),
            codeBlock("    // 2. 解析公钥 Q = (x, y)"),
            codeBlock("    // 3. 范围检查: r, s ∈ [1, n-1]"),
            codeBlock("    // 4. w = s^(-1) mod n"),
            codeBlock("    // 5. u1 = e × w mod n"),
            codeBlock("    // 6. u2 = r × w mod n"),
            codeBlock("    // 7. R = u1×G + u2×Q (Montgomery ladder)"),
            codeBlock("    // 8. 验证 R.x mod n == r"),
            codeBlock("    return VERIFY_SUCCESS or VERIFY_FAILED;"),
            codeBlock("}"),

            heading2("5.5 RVV 向量化接口"),
            para("当定义 __riscv_rvv 时，启用 RVV 加速："),
            para(""),
            codeBlock("#ifdef __riscv_rvv"),
            codeBlock("    #include <riscv_vector.h>"),
            codeBlock("    // 向量化模加/减/约简"),
            codeBlock("    p256_mod_add_vec(), p256_mod_sub_vec(), p256_mod_reduce_vec()"),
            codeBlock("#else"),
            codeBlock("    // 标量回退实现"),
            codeBlock("    p256_mod_add(), p256_mod_sub(), p256_mod_reduce()"),
            codeBlock("#endif"),

            new Paragraph({ children: [new PageBreak()] }),

            // 6. 构建与使用方法
            heading1("6. 构建与使用方法"),
            heading2("6.1 构建"),
            para("前提条件："),
            bullet("RISC-V GCC 工具链 (支持 Zk + V 扩展)"),
            bullet("mbedTLS 库 (用于 P-384 回退和辅助)"),
            bullet("Git 子模块"),
            para(""),
            para("构建命令："),
            codeBlock("# 初始化子模块"),
            codeBlock("git submodule update --init"),
            para(""),
            codeBlock("# 全加速构建 (K + V 扩展)"),
            codeBlock("make build-kv          # SHA + ECDSA P-256 全加速"),
            para(""),
            codeBlock("# K 扩展构建 (仅 SHA)"),
            codeBlock("make build-k           # SHA 用 K intrinsics，ECDSA 用 mbedTLS"),
            para(""),
            codeBlock("# 基础构建 (无扩展)"),
            codeBlock("make build-base        # 纯软件实现"),
            para(""),
            heading2("6.2 构建目标"),
            makeTable(
                ["目标", "扩展", "SHA", "ECDSA P-256"],
                [
                    ["build-kv", "rv64gcv_zk", "K intrinsics", "RVV native"],
                    ["build-k", "rv64gc_zk", "K intrinsics", "mbedTLS"],
                    ["build-base", "rv64gc", "Software", "mbedTLS"],
                ],
                [1800, 1800, 2000, 3760]
            ),
            para(""),
            heading2("6.3 使用方法"),
            heading3("6.3.1 验签接口"),
            para("在代码中使用验签功能："),
            para(""),
            codeBlock("#include \"verify.h\""),
            codeBlock(""),
            codeBlock("int result = verify_image(image_buffer, image_length);"),
            codeBlock("if (result == VERIFY_SUCCESS) {"),
            codeBlock("    // 镜像验证通过"),
            codeBlock("} else {"),
            codeBlock("    // 验证失败 (错误码: -1 到 -4)"),
            codeBlock("}"),
            para(""),
            heading3("6.3.2 创建签名镜像"),
            para("使用 image_tool 创建签名的启动镜像："),
            para(""),
            codeBlock("./image_tool create \\"),
            codeBlock("    --image kernel.bin \\"),
            codeBlock("    --output signed.bin \\"),
            codeBlock("    --type 1 \\"),
            codeBlock("    --hash sha256 \\"),
            codeBlock("    --sig p256"),
            para(""),
            heading2("6.4 错误码"),
            makeTable(
                ["错误码", "含义"],
                [
                    ["0", "VERIFY_SUCCESS - 验签成功"],
                    ["-1", "VERIFY_ERROR_LENGTH - 无效的镜像长度"],
                    ["-2", "VERIFY_ERROR_HEADER - 无效的头字段"],
                    ["-3", "VERIFY_ERROR_HASH - 哈希计算失败"],
                    ["-4", "VERIFY_ERROR_SIGNATURE - 签名验证失败"],
                ],
                [1800, 7560]
            ),

            new Paragraph({ children: [new PageBreak()] }),

            // 7. 总结
            heading1("7. 总结"),
            para("本设计实现了一个完整的 RISC-V 安全启动镜像验签方案："),
            para(""),
            bullet("SHA-256/SHA-384 哈希使用 K 扩展 intrinsics 加速"),
            bullet("ECDSA P-256 验签使用完整的原生 RVV 加速实现"),
            bullet("固定 P-256 曲线参数减少运行时开销"),
            bullet("B 扩展 cmix 实现常数时间运算，抗时序攻击"),
            bullet("Montgomery Ladder 算法保证标量乘法的常数时间特性"),
            bullet("Jacobian 坐标优化点运算效率"),
            bullet("P-256 素数特殊形式加速模约简"),
            para(""),
            para("该设计适用于 RISC-V 架构的安全启动场景，可在支持 K 扩展和向量扩展的 RISC-V 处理器上获得最佳的验签性能。"),

            new Paragraph({ spacing: { before: 720 }, children: [] }),
            new Paragraph({
                alignment: AlignmentType.CENTER,
                spacing: { before: 360, after: 120 },
                children: [new TextRun({ text: "- 文档结束 -", font: "Arial", size: 20, color: "888888", italics: true })]
            }),
        ]
    }]
});

Packer.toBuffer(doc).then(buffer => {
    fs.writeFileSync("secure_boot_design_cn.docx", buffer);
    console.log("Document created: secure_boot_design_cn.docx");
});
