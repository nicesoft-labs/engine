cmake_minimum_required(VERSION 3.18)
project(gost-engine LANGUAGES C)

set(CMAKE_C_STANDARD 90)

set(GOST_89_SOURCE_FILES
        gost89.c
        gost89.h
)

set(GOST_HASH_SOURCE_FILES
        gosthash.c
        gosthash.h
)

set(GOST_HASH_2012_SOURCE_FILES
        gosthash2012.c
        gosthash2012.h
        gosthash2012_const.h
        gosthash2012_precalc.h
        gosthash2012_ref.h
        gosthash2012_sse2.h
)

set(GOST_GRASSHOPPER_SOURCE_FILES
        gost_grasshopper.h
        gost_grasshopper_core.h
        gost_grasshopper_core.c
        gost_grasshopper_defines.h
        gost_grasshopper_defines.c
        gost_grasshopper_math.h
        gost_grasshopper_galois_precompiled.c
        gost_grasshopper_precompiled.c
        gost_grasshopper_cipher.h
        gost_grasshopper_cipher.c
)

set(GOST_ERR_SOURCE_FILES
        e_gost_err.c
        e_gost_err.h
)

set(GOST_CORE_SOURCE_FILES
        gost_ameth.c
        gost_pmeth.c
        gost_ctl.c
        gost_asn1.c
        gost_crypt.c
        gost_keywrap.c
        gost_keywrap.h
        gost_md.c
        gost_md2012.c
        gost_omac.c
        gost_omac_acpkm.c
        gost_gost2015.c
        gost_lcl.h
        gost_params.c
        gost_keyexpimp.c
)

set(GOST_EC_SOURCE_FILES
        gost_ec_keyx.c
        gost_ec_sign.c
        ecp_id_GostR3410_2001_CryptoPro_A_ParamSet.c
        ecp_id_GostR3410_2001_CryptoPro_B_ParamSet.c
        ecp_id_GostR3410_2001_CryptoPro_C_ParamSet.c
        ecp_id_GostR3410_2001_TestParamSet.c
        ecp_id_tc26_gost_3410_2012_256_paramSetA.c
        ecp_id_tc26_gost_3410_2012_512_paramSetA.c
        ecp_id_tc26_gost_3410_2012_512_paramSetB.c
        ecp_id_tc26_gost_3410_2012_512_paramSetC.c
)

set(GOST_OMAC_SOURCE_FILES
        gost_omac.c
        gost_omac_acpkm.c
)

set(GOST_LIB_SOURCE_FILES
        ${GOST_CORE_SOURCE_FILES}
        ${GOST_89_SOURCE_FILES}
        ${GOST_HASH_SOURCE_FILES}
        ${GOST_HASH_2012_SOURCE_FILES}
        ${GOST_GRASSHOPPER_SOURCE_FILES}
        ${GOST_EC_SOURCE_FILES}
        ${GOST_OMAC_SOURCE_FILES}
)

set(GOST_ENGINE_SOURCE_FILES
        gost_eng.c
)

set(GOST_PROV_SOURCE_FILES
        gost_prov.c
        gost_prov_cipher.c
        gost_prov_digest.c
        gost_prov_mac.c
)

add_library(gost_core STATIC ${GOST_LIB_SOURCE_FILES})
set_target_properties(gost_core PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_libraries(gost_core PUBLIC OpenSSL::Crypto)

add_library(gost_err STATIC ${GOST_ERR_SOURCE_FILES})
set_target_properties(gost_err PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_libraries(gost_err PUBLIC OpenSSL::Crypto)

add_subdirectory(libprov)

add_library(gost_prov MODULE ${GOST_PROV_SOURCE_FILES} ${GOST_ENGINE_SOURCE_FILES})
set_target_properties(gost_prov PROPERTIES
        PREFIX ""
        OUTPUT_NAME "gostprov"
        SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX}
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/ossl-modules
)

target_compile_definitions(gost_prov PRIVATE BUILDING_GOST_PROVIDER OPENSSL_NO_DYNAMIC_ENGINE)
target_link_libraries(gost_prov PRIVATE gost_core gost_err libprov OpenSSL::Crypto)

target_include_directories(gost_prov PRIVATE
        ${OPENSSL_INCLUDE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../openssl/providers/common/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../openssl/providers/implementations/include
        ${CMAKE_CURRENT_SOURCE_DIR}/libprov/include
)

