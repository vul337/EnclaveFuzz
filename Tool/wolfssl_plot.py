#!/usr/bin/python3
import numpy as np
import matplotlib.pyplot as plt

# 数据
categories = ['RNG', 'AES-128-CBC-enc', 'AES-128-CBC-dec', 'AES-192-CBC-enc', 'AES-192-CBC-dec',
              'AES-256-CBC-enc', 'AES-256-CBC-dec', 'AES-128-GCM-enc', 'AES-128-GCM-dec',
              'AES-192-GCM-enc', 'AES-192-GCM-dec', 'AES-256-GCM-enc', 'AES-256-GCM-dec',
              'GMAC Table 4-bit', 'RABBIT', '3DES', 'MD5', 'SHA', 'SHA-256', 'HMAC-MD5',
              'HMAC-SHA', 'HMAC-SHA256', 'PBKDF2', 'RSA 2048 public', 'RSA 2048 private',
              'DH 2048 key gen', 'DH 2048 agree', 'ECC [ SECP256R1] 256 key gen',
              'ECDHE [ SECP256R1] 256 agree', 'ECDSA [ SECP256R1] 256 sign',
              'ECDSA [ SECP256R1] 256 verify']
values = [[106.077, 61.308, 108.168, 43.73],
          [251.317, 91.754, 251.311, 62.529],
          [282.884, 84.976, 282.782, 59.904],
          [215.838, 77.342, 217.25, 51.281],
          [242.235, 72.125, 240.302, 50.397],
          [189.815, 68.486, 191.156, 44.195],
          [207.74, 61.241, 207.73, 43.509],
          [138.288, 61.309, 136.996, 41.272],
          [137.73, 63.661, 136.996, 41.337],
          [126.923, 54.501, 125.769, 36.679],
          [126.625, 56.317, 125.783, 36.788],
          [117.412, 48.961, 116.484, 33.385],
          [117.144, 49.626, 116.486, 32.815],
          [331.98, 156.852, 323.564, 114.98],
          [647.568, 319.952, 708.844, 178.028],
          [28.359, 19.051, 28.279, 15.082],
          [522.751, 481.025, 523.766, 396.934],
          [584.548, 421.198, 565.985, 340.312],
          [232.95, 141.97, 234.223, 118.911],
          [522.698, 479.287, 523.089, 396.886],
          [584.402, 422.433, 587.94, 337.765],
          [232.923, 143.199, 234.445, 119.135],
          [28.734, 16.989, 27.296, 12.894],
          [19053.718, 12745.194, 7221.802, 2557.741],
          [281.806, 170.21, 139.03, 43.464],
          [1872.476, 1324.989, 312.464, 114.673],
          [867.157, 651.688, 309.466, 114.778],
          [1582.649, 707.854, 8314.276, 2513.205],
          [1564.898, 720.549, 4044.342, 1292.552],
          [1512.423, 640.553, 6414.134, 1941.938],
          [2378.532, 1008.817, 3710.553, 1219.136]]

# 转置数据
values_transposed = np.array(values).T.tolist()

# 设置图表参数
plt.figure(figsize=(16, 6))
bar_width = 0.2
index = range(len(categories))

# 绘制条形图
plt.bar(index, values_transposed[0], width=bar_width, label="nonSGX")
plt.bar(
    [i + bar_width for i in index],
    values_transposed[1],
    width=bar_width,
    label="nonSGX+ASan",
)
plt.bar(
    [i + 2 * bar_width for i in index],
    values_transposed[2],
    width=bar_width,
    label="SGX",
)
plt.bar(
    [i + 3 * bar_width for i in index],
    values_transposed[3],
    width=bar_width,
    label="SGX+SGXSan",
)

# 设置坐标轴标签和标题
# plt.xlabel("Items")
plt.ylabel("Throughput (log scale)")
plt.title("WolfSSL Benchmark")

unit_labels = [cat + " (KB/s)" if i < 23 else cat + " (op/s)" for i, cat in enumerate(categories)]
# # 设置刻度标签和图例，并将文字倾斜展示
plt.xticks([i + 1.5 * bar_width for i in index], unit_labels, rotation=45)
plt.legend()

# 设置纵轴为对数比例
plt.yscale("log")

# 显示图表
plt.tight_layout()
plt.savefig("table.png")
plt.savefig("table.pdf", format="pdf")