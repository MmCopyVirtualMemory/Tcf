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
    U64 gnames = 0x64A3480;
    struct
    {
        U64 name_length = 0xa;
        U64 name_start = 0xe;
    }name_entry;
    //world
    U64 gworld = 0x662D868;
    U64 dword1 = 0x662F884;
    U64 dword2 = 0x662F88C;
    U64 dword3 = 0x662F874;
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


