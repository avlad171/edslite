cmake_minimum_required(VERSION 3.22)

add_definitions(-DANDROID )
include_directories(src/main/native/crypto)

find_library( log-lib
              log )

add_library( edsxts
			 SHARED
             src/main/native/xts/edsxts.c )

target_link_libraries( edsxts                       
                       ${log-lib} )

add_library( edsaes
			 SHARED
             src/main/native/aes/edsaes.c 
             src/main/native/aes/aescrypt.c 
             src/main/native/aes/aeskey.c 
             src/main/native/aes/aestab.c )

target_link_libraries( edsaes
                       ${log-lib} )

add_library( edsserpent
			 SHARED
             src/main/native/serpent/edsserpent.c
             src/main/native/serpent/serpent.c )

target_link_libraries( edsserpent
                       ${log-lib} )

add_library( edstwofish
			 SHARED
             src/main/native/twofish/edstwofish.c
             src/main/native/twofish/twofish.c )

add_library( edsripemd160
			 SHARED
             src/main/native/ripemd160/edsripemd160.c )

target_link_libraries( edsripemd160
                       ${log-lib} )

add_library( edswhirlpool
			 SHARED
             src/main/native/whirlpool/edswhirlpool.c
             src/main/native/whirlpool/whirlpool.c )

target_link_libraries( edswhirlpool
                       ${log-lib} )

add_library( fdraio
			 SHARED
             src/main/native/fdraio/fdraio.c )

target_compile_definitions( fdraio
        					PRIVATE _FILE_OFFSET_BITS=64 )

target_link_libraries( fdraio
                       ${log-lib} )

add_library( localxts
			 SHARED
             src/main/native/localxts/localxts.c )

target_compile_definitions( localxts
        					PRIVATE _FILE_OFFSET_BITS=64 )

target_link_libraries( localxts
                       edsxts
                       ${log-lib} )

add_library( edsctr
       SHARED
             src/main/native/ctr/edsctr.c )

target_link_libraries( edsctr
                       ${log-lib} )

add_library( edscbc
       SHARED
             src/main/native/cbc/edscbc.c )

target_link_libraries( edscbc
                       ${log-lib} )

add_library( edscfb
       SHARED
             src/main/native/cfb/edscfb.c )

target_link_libraries( edscfb
                       ${log-lib} )
add_library( edsgost
       SHARED
             src/main/native/gost/edsgost.c
             src/main/native/gost/gost89.c )

# Read-only ext2/3/4 driver (lwext4 + EDS glue). See src/main/native/lwext4/EDS-PATCHES.txt
file(GLOB LWEXT4_SRC src/main/native/lwext4/src/*.c)
list(FILTER LWEXT4_SRC EXCLUDE REGEX ".*ext4_mkfs\\.c$")
add_library( edsext4
             SHARED
             ${LWEXT4_SRC}
             src/main/native/ext4/edsext4_core.c
             src/main/native/ext4/edsext4_jni.c )
target_include_directories( edsext4 PRIVATE src/main/native/lwext4/include src/main/native/ext4 )
target_compile_definitions( edsext4 PRIVATE
        CONFIG_USE_DEFAULT_CFG=1 CONFIG_EXT4_MOUNTPOINTS_COUNT=8 CONFIG_EXT4_BLOCKDEVS_COUNT=8
        CONFIG_BLOCK_DEV_CACHE_SIZE=64 CONFIG_DEBUG_PRINTF=0 CONFIG_HAVE_OWN_ASSERT=0
        CONFIG_HAVE_OWN_ERRNO=0 _FILE_OFFSET_BITS=64 )
# Assertions stay on (abort beats memory corruption on a malformed volume).
target_compile_options( edsext4 PRIVATE -UNDEBUG -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wno-unused-parameter )
target_link_libraries( edsext4 ${log-lib} )

# LUKS2 crypto (Argon2 reference + AES-XTS on Gladman AES). Read-only: decrypt only.
add_library( edsluks
             SHARED
             src/main/native/luks/edsluks.c
             src/main/native/aes/aeskey.c src/main/native/aes/aescrypt.c src/main/native/aes/aestab.c
             src/main/native/argon2/src/argon2.c src/main/native/argon2/src/core.c
             src/main/native/argon2/src/encoding.c src/main/native/argon2/src/ref.c
             src/main/native/argon2/src/thread.c src/main/native/argon2/src/blake2/blake2b.c )
target_include_directories( edsluks PRIVATE src/main/native/aes src/main/native/crypto
        src/main/native/argon2/include src/main/native/argon2/src )
target_compile_definitions( edsluks PRIVATE AES_128 )
target_compile_options( edsluks PRIVATE -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wno-unused-function )
target_link_libraries( edsluks ${log-lib} )

include(CMakeLists-full.txt)
include(CMakeLists-fsm.txt)
