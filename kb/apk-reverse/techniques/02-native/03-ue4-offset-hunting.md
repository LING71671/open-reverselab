# UE4 引擎游戏偏移发现

## 场景

目标手游使用 Unreal Engine 4，核心逻辑在 `libUE4.so`。需要找到 Character/Actor 关键属性偏移（血量、坐标、队伍ID、武器等）。

## 输入信号

- `lib/arm64-v8a/libUE4.so` 存在（150MB+）
- 符号被 strip 但类名仍在 `FName` 池中
- 游戏画面为 3D 射击/动作类（UE4 特征）
- 包体大 + 使用 OBB

## UE4 类继承链速查 (FPS/TPS 通用)

```
UObject
├── AActor
│   ├── APawn
│   │   └── ACharacter
│   │       ├── ASTExtraCharacter (FPS类游戏通用)
│   │       └── ASTExtraBaseCharacter
│   └── AWeapon
│       ├── ASTExtraWeapon
│       └── ASTExtraShootWeapon
├── UActorComponent
│   ├── UPrimitiveComponent
│   │   ├── USkeletalMeshComponent  (骨骼)
│   │   └── UStaticMeshComponent
│   └── UWeaponManagerComponent
└── UPlayerState
    └── AUAEPlayerState
```

## 实战偏移发现方法

### 方法 1: 静态分析 UE4 SDK dump

```bash
# UE4Dumper 在目标进程内运行 → dump GNames/GObjects → 生成 SDK
# 产出: SDK.hpp 包含所有类的完整偏移定义

# 类定义示例 (自动生成):
class ASTExtraCharacter : public ACharacter {
public:
    float Health;               // 0x0E78
    float HealthMax;            // 0x0E7C
    int8_t TeamID;              // 0x0E20
    bool bIsAI;                 // 0x0E21
    FString PlayerName;         // 0x0D50
};
```

### 方法 2: FName 池字符串搜索

```bash
# libUE4.so 中搜索类名和属性名:
strings libUE4.so | grep -i "Health\|TeamID\|Character\|Weapon\|RootComponent"
# 每个 FName 在池中有索引, 通过 GNames 表解析
```

### 方法 3: 运行时特征法

```c
// 已知: 血量初始值通常是 100 或 100.0
// 搜索策略: 在 libUE4.so 偏移 0x0E60~0x0EC0 范围扫描 float=100.0
// 验证: 受到伤害后该值下降 → 确认是 Health
```

### 方法 4: 指针链定位 (最实战)

```cpp
// UE4 FPS 游戏经典 Actor 链
// RootComponent → RelativeLocation → X/Y/Z
long Actor = readPtr(actorList + i * 8);
long RootComponent = readPtr(Actor + 0x190);     // AActor::RootComponent
long RelativeLocation = RootComponent + 0x1A0;   // USceneComponent::RelativeLocation
float x = readFloat(RelativeLocation);            // FVector::X
float y = readFloat(RelativeLocation + 0x4);      // FVector::Y
float z = readFloat(RelativeLocation + 0x8);      // FVector::Z

// 武器链
long WeaponManager = readPtr(Actor + 0x0B68);     // STExtraBaseCharacter::WeaponManagerComponent
long CurrentWeapon = readPtr(WeaponManager + 0x218); // WeaponManagerComponent::CurrentWeaponReplicated
long WeaponEntity = readPtr(CurrentWeapon + 0x190);  // STExtraWeapon::WeaponEntityComp
float bulletSpeed = readFloat(WeaponEntity + 0x7C0); // ShootWeaponEntity::BulletFireSpeed
```

## Frida 动态验证脚本

```javascript
var libbase = Module.findBaseAddress("libUE4.so")
var GWorld = libbase.add(0xOFFSET_GWORLD)  // 全局 UWorld 指针

function readPtr(addr) { return Memory.readPointer(addr) }
function readFloat(addr) { return Memory.readFloat(addr) }

// 遍历 Actor 列表
var PersistentLevel = readPtr(readPtr(GWorld) + 0x30)
var Actors = readPtr(PersistentLevel + 0x98)
var ActorCount = Memory.readInt(PersistentLevel + 0xA0)

for (var i = 0; i < ActorCount; i++) {
    var Actor = readPtr(Actors.add(i * 8))
    if (Actor.isNull()) continue
    // 验证: 读取 RootComponent → check 非空
    var Root = readPtr(Actor.add(0x190))
    if (Root.isNull()) continue
    var X = readFloat(Root.add(0x1A0))
    var Y = readFloat(Root.add(0x1A4))
    var Z = readFloat(Root.add(0x1A8))
    console.log(`[Actor ${i}] X=${X} Y=${Y} Z=${Z}`)
}
```

## 常见误判

- UE4 版本不同，UWorld/GObject/GNames 偏移不同 → 先用 UE4Dumper 确认
- ActorList 中大量 nullptr → 跳过空指针（引擎特性，已销毁对象不实时清理）
- FName 字典在 strip 后不可读 → 用 CheatEngine 或 Frida dump runtime 字符串
- 属性偏移在不同子类中偏移不同 → 注意继承层级和虚函数表位移

## 攻击链

```
UE4 游戏 → UE4Dumper dump SDK → 定位 GWorld/GObject 全局偏移
→ search libUE4.so strings 找类名 → 验证 Actor 继承链 → 确定关键属性偏移
→ Frida 脚本遍历 Actor 列表 → 验证血量/坐标变化 → 锁定最终偏移
```

## MCP 工具映射

AI Agent 可调用以下 MCP 工具自动完成或加速上述攻击链步骤：

| 攻击链步骤 | MCP 工具 | 说明 |
|-----------|---------|------|
| Frida 枚举 GNames/GObjects | `android_frida_run_script` | 运行 Frida 脚本枚举 GNames/GObjects |
| 分析 libUE4.so | `ghidra_headless_analyze` | 分析 libUE4.so |
