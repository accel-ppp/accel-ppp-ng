INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})

SET(sources
	vpphooks.c
	vppiputils.c
	vpppoe.c
	vpppolicer.c
	vpputils.c
)

ADD_LIBRARY(vpp SHARED ${sources})

TARGET_LINK_LIBRARIES(vpp vapiclient vlibapi vlib)
set_property(TARGET vpp PROPERTY CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
set_property(TARGET vpp PROPERTY INSTALL_RPATH ${CMAKE_INSTALL_PREFIX}/lib${LIB_SUFFIX}/accel-ppp)

INSTALL(TARGETS vpp LIBRARY DESTINATION lib${LIB_SUFFIX}/accel-ppp)
