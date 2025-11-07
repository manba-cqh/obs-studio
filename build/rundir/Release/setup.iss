; ---------- 基本安装配置 ----------
[Setup]
AppName=Capture
AppVersion=1.0.0
; 默认安装目录，可自行修改
DefaultDirName={pf}\Capture
DefaultGroupName=Capture
; 不让用户自选开始菜单目录
DisableProgramGroupPage=yes
OutputBaseFilename=CaptureSetup
; 压缩方式
Compression=lzma2
SolidCompression=yes

; ---------- 文件复制 ----------
[Files]
; 打包当前目录下所有文件和文件夹
Source: "{#SourcePath}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

; ---------- 开始菜单/桌面快捷方式（可选） ----------
[Icons]
Name: "{autoprograms}\Capture"; Filename: "{app}\bin\64bit\obs64.exe"
; Tasks: desktopicon
Name: "{autodesktop}\Capture"; Filename: "{app}\bin\64bit\obs64.exe"

; ---------- 自启动（写注册表 Run 项） ----------
[Registry]
; 当前用户自启动：开机执行 {app}\obs64.exe --minimize-to-tray（参数可自定义）
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
    ValueType: string; ValueName: "Capture"; \
    ValueData: """{app}\bin\64bit\obs64.exe"" --startstreaming --minimize-to-tray"; \
    Flags: uninsdeletevalue

; ---------- 安装完成后执行 ----------
[Run]
; 安装结束立即运行一次（可选）
Filename: "{app}\bin\64bit\obs64.exe"; Description: "启动 Capture"; Flags: nowait postinstall skipifsilent

; ---------- 卸载后清理（注册表项已通过 Flags 自动删除） ----------
[UninstallDelete]
; 如果还想删除特定文件，可加类似项
; Type: files; Name: "{app}\Scenes.json"