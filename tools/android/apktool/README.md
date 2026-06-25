# Apktool

APK 解包和重打包工具。

## 下载

- 官网：https://apktool.org/
- 下载 `apktool.jar` 和 `apktool.bat`（Windows wrapper）
- 将两个文件放入本目录

## 使用

```bash
java -jar apktool.jar d target.apk -o output_dir   # 解包
java -jar apktool.jar b output_dir -o repacked.apk  # 重打包
```
