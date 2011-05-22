@echo off
del   *.ncb /S /Q
del   *.suo /S /Q /F /A:H
del   *.user /S /Q
del   BuildLog.htm /S /Q
del    dcapi.lib  /S /Q
del    *.exp /S /Q
del    *.dll /S /Q
del    *.pdb /S /Q
del    *.sys  /S /Q
del    *.exe  /S /Q
del    debug\*.lib  /S /Q
del    release\*.lib  /S /Q
del    *.log  /S /Q
del    *.obj  /S /Q
del    *.aps  /S /Q
del    *.ilk  /S /Q
del    boot\bin\* /S /Q

rmdir release\amd64\obj /S /Q
rmdir release\i386\obj /S /Q
rmdir release\boot\obj /S /Q

rmdir debug\amd64\obj /S /Q
rmdir debug\i386\obj /S /Q
rmdir debug\boot\obj /S /Q


