include(ExternalProject)

if(${CMAKE_HOST_SYSTEM_NAME} STREQUAL "Windows")
	ExternalProject_Add(lsarelayx_client
		SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}
                INSTALL_COMMAND msbuild /p:Configuration=Release /t:lsarelayx:pack  && ${CMAKE_COMMAND}  -E copy ${CMAKE_CURRENT_SOURCE_DIR}/bin/Release/net48/lsarelayx.exe ${CMAKE_INSTALL_PREFIX}/lsarelayx.exe
		BUILD_IN_SOURCE TRUE
		BUILD_ALWAYS TRUE
		BUILD_COMMAND msbuild /p:Configuration=Release /m lsarelayx.sln -target:restore COMMAND msbuild /p:Configuration=Release /m lsarelayx.sln -target:lsarelayx:rebuild
	)
else()
	ExternalProject_Add(lsarelayx_client
		SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}
                INSTALL_COMMAND dotnet msbuild -clp:disableconsolecolor lsarelayx.sln -property:Configuration=Release -target:lsarelayx:pack && ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/bin/Release/net48/lsarelayx.exe ${CMAKE_INSTALL_PREFIX}/lsarelayx.exe
		BUILD_IN_SOURCE TRUE
		BUILD_ALWAYS TRUE
		BUILD_COMMAND dotnet restore COMMAND dotnet msbuild -clp:disableconsolecolor lsarelayx.sln -property:Configuration=Release -target:lsarelayx 
	)
endif()


