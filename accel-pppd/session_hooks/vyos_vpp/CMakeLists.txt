INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})

SET(sources
	vpphooks.c
	vppiputils.c
	vpppoe.c
	vpppolicer.c
	vpputils.c
)

ADD_LIBRARY(vyos_vpp SHARED ${sources})

TARGET_LINK_LIBRARIES(vyos_vpp vapiclient vlibapi vlib)
set_property(TARGET vyos_vpp PROPERTY CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
set_property(TARGET vyos_vpp PROPERTY INSTALL_RPATH ${CMAKE_INSTALL_PREFIX}/lib${LIB_SUFFIX}/accel-ppp)

INSTALL(TARGETS vyos_vpp LIBRARY DESTINATION lib${LIB_SUFFIX}/accel-ppp)
