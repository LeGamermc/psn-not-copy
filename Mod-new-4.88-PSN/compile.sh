echo "[COMPILATION]: Explore (vsh module)..."
wine scetool.exe -v --compress-data=TRUE --sce-type=SELF --self-type=NPDRM --np-app-type=SPRX --template=explore_plugin_backup.sprx --encrypt explore_plugin.prx explore_plugin.sprx
echo "[COMPILATION]: NpSingin (singup/singin module)..."
wine scetool.exe -v --compress-data=TRUE --sce-type=SELF --self-type=NPDRM --np-app-type=SPRX --template=npsignin_plugin_backup.sprx --encrypt npsignin_plugin.prx npsignin_plugin.sprx
echo "[COMPILATION]: Eula_net (eula shit)..."
wine scetool.exe -v --compress-data=TRUE --sce-type=SELF --self-type=NPDRM --np-app-type=SPRX --template=eula_net_plugin_backup.sprx --encrypt eula_net_plugin.prx eula_net_plugin.sprx
echo "[COMPILATION]: REGCAM (Account registration)..."
wine scetool.exe -v --compress-data=TRUE --sce-type=SELF --self-type=NPDRM --np-app-type=SPRX --template=regcam_plugin_backup.sprx --encrypt regcam_plugin.prx regcam_plugin.sprx
echo "[COMPILATION]: NAS (Network Authentication System)..."
wine scetool.exe -v --compress-data=TRUE --sce-type=SELF --self-type=NPDRM --np-app-type=SPRX --template=nas_plugin_backup.sprx --encrypt nas_plugin.prx nas_plugin.sprx
echo "[COMPILATION]: New store (legacystore of the ps3 [yea pretty ironic])..."
wine scetool.exe -v --compress-data=TRUE --sce-type=SELF --self-type=NPDRM --np-app-type=SPRX --template=newstore_plugin_backup.sprx --encrypt newstore_plugin.prx newstore_plugin.sprx
echo "[COMPILATION]: VSH..."
wine scetool.exe -v --compress-data=TRUE --sce-type=SELF --self-type=NPDRM --np-app-type=SPRX --template=vsh_backup.self --encrypt vsh.elf vsh.self
echo "[COMPILATION]: DONE"
