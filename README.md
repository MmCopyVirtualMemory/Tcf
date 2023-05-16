# Tcf
The Cycle Frontier Reverse Engineering

# World:
```
"No world was found for object (%s) passed in to UEngine::GetWorldFromContextObject()."
F3 0F 2C 05 ? ? ? ? 8B 15 ? ? ? ? 48 8D 35 ? ? ? ? 03 15 ? ? ? ? 48 FF C2 81 E2 ? ? ? ? C1 F8 05 F7 D0 48 98 48 25 ? ? ? ? 48 0B D0 48 8B 34 D6
```
# Names:
```
"ERROR NAME SIZE EXCEEDED"
74 09 48 8D 15 ? ? ? ? EB 16
```
# Objects:
```
"NewObject with empty name can't be used to create default"
```

# Offsets: 5/11/2023
```cpp
struct 
{
    //names
    U64 gnames = 0x64ada40;
    struct
    {
        U64 name_length = 0x4;
        U64 name_start = 0x8;
    }name_entry;
    //world
    U64 gworld = 0x6638e28;
    U64 dword1 = 0x663ae48;
    U64 dword2 = 0x663ae54;
    U64 dword3 = 0x663ae34;
    struct
    {
        U64 levels = 0x1f80; //Levels
        U64 owning_game_instance = 0x2000; //OwningGameInstance
    }world; //UWorld
    struct
    {
        U64 actors = 0xb8;
    }level; //ULevel
    struct
    {
        U64 local_players = 0x58; //LocalPlayers
    }game_instance; //UGameInstance
    struct
    {
        U64 player_controller = 0x50; //PlayerController
    }local_player; //ULocalPlayer
    struct
    {
        U64 control_rotation = 0x2d0; //ControlRotation
        U64 acknowledged_pawn = 0x298; //AcknowledgedPawn
        U64 camera_manager = 0x328; //CameraManager
        U64 runtime_weapon_component = 0x8c0; //m_runtimeWeaponComponent
    }player_controller; //APlayerController
    struct
    {
        U64 last_frame_camera_cache_private = 0x1970;//LastFrameCameraCachePrivate
    }player_camera_manager; //APlayerCameraManager
    struct
    {
        U64 comparison_index = 0x30; //Name.ComparisonIndex
        U64 root_component = 0x170; //RootComponent
    }actor; //AActor
    struct
    {
        U64 player_state = 0x288; //PlayerState
        U64 mesh = 0x2c8;
        U64 health_component = 0x518;
        U64 stamina_component = 0x748;
    }character; //ACharater
    struct
    {
        U64 relative_location = 0x120; //RelativeLocation
    }scene_component; //USceneComponent
    struct
    {
        U64 player_name_private = 0x368; //PlayerNamePrivate
    }player_state; //APlayerState
    struct
    {
        U64 component_to_world = 0x1e0;
        U64 bone_array = 0x4d0;
    }mesh;
    struct 
    {
        U64 health = 0x2f0; //m_currentHealth
    }health_component; //UYHealthComponent
    struct 
    {
        U64 stamina = 0x140; //m_currentStamina
    }stamina_component; //UYStaminaComponent
    struct 
    {
        U64 current_weapon = 0x7c8; //
    }weapon_component; //UYWeaponPlayerControllerRuntimeComponent
    struct 
    {
        //spread
        U64 default_weapon_spread = 0x84; //m_defaultWeaponSpread
        U64 weapon_spread_increase_speed = 0x88; //m_weaponSpreadIncreaseSpeed
        U64 weapon_spread_decrease_speed = 0x8C; //m_weaponSpreadDecreaseSpeed
        U64 weapon_spread_max = 0x90; //m_weaponSpreadMax
        //recoil
    }weapon_data; //FYWeaponTuningDataTableRow
}off;
```

# Kewl Fnames:
```
PRO_PlayerCharacter_C
YPickup_Base_BP_C | YPickup_QuestItem_BP_C | YPickUp_Mineral_BP_C
YBagContainer_BP_C | AA_LootContainers_BP_C | AA_PowerUp_LootContainer_BP

AIChar_GlowBeetle_Blast_BP_C | AIChar_GlowBeetle_Acid_BP_C
AIChar_Strider_BP_C
AIChar_Rattler_BP_C
AIChar_Weremole_BP_C
AIChar_Howler_BP_C

AA_PowerUpBattery_BP_C
```

# WIP AutoUpdater Ft Python
```py
prospect_file = open('Prospect-Win64-Shipping.exe.bin', 'rb')
prospect = prospect_file.read()

def CheckMatch(index, pattern, mask, size):
    comparison_index = 0
    while comparison_index < size:
        byte_match = ord(pattern[comparison_index]) == prospect[index + comparison_index]
        if mask[comparison_index] != '?' and not byte_match:
            return False
        comparison_index+=1
    return True

def PatternScan(pattern, mask, size):
    index = 0
    while index < prospect_file.tell() - size:
        if CheckMatch(index, pattern, mask, size):
            return index
        index+=1
    return -1

def Rva(instruction, size):
    rip = instruction + size
    dummy_byte_array = []
    index = 0
    while index < 4:
        dummy_byte_array.append(prospect[instruction + size - 4 + index])
        index+=1
    rva = int.from_bytes(dummy_byte_array, "little", signed=False)
    return rip + rva

world_cvttss2si_instruction = PatternScan(
        "\xF3\x0F\x2C\x05\x00\x00\x00\x00\x8B\x15\x00\x00\x00\x00\x48\x8D\x35\x00\x00\x00\x00\x03\x15\x00\x00\x00\x00\x48\xFF\xC2\x81\xE2\x00\x00\x00\x00\xC1\xF8\x05\xF7\xD0\x48\x98\x48\x25\x00\x00\x00\x00\x48\x0B\xD0\x48\x8B\x34\xD6", 
        "xxxx????xx????xxx????xx????xxxxx????xxxxxxxxx????xxxxxxx", 56)
world_mov_instruction = world_cvttss2si_instruction + 8
world_lea_instruction = world_mov_instruction + 6
world_add_instruction = world_lea_instruction + 7
dword1 = Rva(world_cvttss2si_instruction, 8)
dword3 = Rva(world_mov_instruction, 6)
gworld = Rva(world_lea_instruction, 7)
dword2 = Rva(world_add_instruction, 6)
print("U64 gworld = " + hex(gworld))
print("U64 dword1 = " + hex(dword1))
print("U64 dword2 = " + hex(dword2))
print("U64 dword3 = " + hex(dword3))

names_lea_instruction = PatternScan(
        "\x74\x09\x48\x8D\x15\x00\x00\x00\x00\xEB\x16", 
        "xxxxx????xx", 11) + 2
gnames = Rva(names_lea_instruction, 7)
print("U64 gnames = " + hex(gnames))
```
