#### **For VirtualBox:** (`build-vbox.ps1`)


& "D:\VirualBox\VBoxManage.exe" createvm --name "AutomatedWin10" --register
& "D:\VirualBox\VBoxManage.exe" modifyvm "AutomatedWin10" --memory 4096 --cpus 2 --ostype "Windows10_64"
& "D:\VirualBox\VBoxManage.exe" createmedium disk --filename "C:\ISO Folder\AutomatedWin10.vdi" --size 40000
& "D:\VirualBox\VBoxManage.exe" storagectl "AutomatedWin10" --name "SATA Controller" --add sata --controller IntelAhci
& "D:\VirualBox\VBoxManage.exe" storageattach "AutomatedWin10" --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium "C:\ISO Folder\AutomatedWin10.vdi"
& "D:\VirualBox\VBoxManage.exe" storagectl "AutomatedWin10" --name "IDE Controller" --add ide
& "D:\VirualBox\VBoxManage.exe" storageattach "AutomatedWin10" --storagectl "IDE Controller" --port 0 --device 0 --type dvddrive --medium "C:\ISO Folder\Windows+11+Dev+(OS+Build+21996.1).iso"
& "D:\VirualBox\VBoxManage.exe" storageattach "AutomatedWin10" --storagectl "IDE Controller" --port 1 --device 0 --type dvddrive --medium "C:\ISO Folder\answer.iso"
& "D:\VirualBox\VBoxManage.exe" startvm "AutomatedWin10"