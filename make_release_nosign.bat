@echo off
set path=%path%;C:\Program Files\Microsoft Visual Studio 9.0\Common7\IDE\;C:\Program Files\Inno Setup 5
call clean.bat

devenv dcrypt.sln /Build "Release|win32"
devenv dcrypt.sln /Build "Release|x64"

pushd setup
iscc /cc setup.iss
popd

call make_bartpe.bat

pause