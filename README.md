# fuin

Android DEX Packer

## 概要

AndroidアプリのDEXファイルを暗号化し、サーバー管理の鍵で保護するパッカーツール。

## アーキテクチャ

```
[元のAPK]
    ↓ アップロード
[Webサーバー]
    - classes.dex をAES暗号化
    - assets/encrypted.dex に配置
    - AndroidManifest.xml のApplicationをスタブに書き換え
    - APKを再パック → 署名
    ↓
[保護済みAPK]

[実行時]
スタブ Application.attachBaseContext()
    ↓
サーバーに鍵リクエスト（端末ID・署名検証）
    ↓
DEXを復号 → DexClassLoader でロード
    ↓
元のApplicationに差し替え → 通常起動
```

## 特徴

- 鍵をサーバー側で管理 → 静的解析だけでは鍵が取れない
- 端末ID・APK署名の検証で改ざん検知
- サーバー側で鍵を無効化できる

## 構成

- `packer/` - Pythonパッカー本体
- `stub/` - Androidスタブアプリ
- `server/` - 鍵管理サーバー
