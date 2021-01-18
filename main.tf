provider "aws" {
  region                  = "us-east-2"
  shared_credentials_file = "/Users/felix/.aws/credentials"
  profile                 = "cncore"
}


# 1. Create vpc

resource "aws_vpc" "my-lab-vpc" {
  cidr_block       = "10.0.0.0/16"

  tags = {
    Name = "My Lab VPC"
  }
}


# 2. Create Internet Gateway

resource "aws_internet_gateway" "prod-gw" {
  vpc_id = aws_vpc.my-lab-vpc.id

  tags = {
    Name = "prod-gw"
  }
}



# 3. Create Custom route table

resource "aws_route_table" "public-route-table" {
  vpc_id = aws_vpc.my-lab-vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.prod-gw.id
  }


  tags = {
    Name = "public-routetable"
  }
}


# 4. Create a subnet
resource "aws_subnet" "public-subnet-1" {
  vpc_id     = aws_vpc.my-lab-vpc.id
  cidr_block = "10.0.1.0/24"
  availability_zone = "us-east-2a"

  tags = {
    Name = "Public Subnet 1"
  }
}


resource "aws_subnet" "public-subnet-2" {
  vpc_id     = aws_vpc.my-lab-vpc.id
  cidr_block = "10.0.2.0/24"
  availability_zone = "us-east-2b"

  tags = {
    Name = "Public Subnet 2"
  }
}


# 5. Associate subnet with Route table

resource "aws_route_table_association" "public-association-1" {
  subnet_id      = aws_subnet.public-subnet-1.id
  route_table_id = aws_route_table.public-route-table.id
}

resource "aws_route_table_association" "public-association-2" {
  subnet_id      = aws_subnet.public-subnet-2.id
  route_table_id = aws_route_table.public-route-table.id
}


# 6. Create security group to allow port 22, 80, 443

resource "aws_security_group" "cncorelab-sg" {
  name        = "cncorelab-sg"
  description = "Allow inbound traffic from limited ports and SrcIP"
  vpc_id      = aws_vpc.my-lab-vpc.id

    # Allow ssh
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["218.2.208.75/32", "18.162.103.100/32", "36.152.113.203/32", "58.212.197.96/32", aws_vpc.my-lab-vpc.cidr_block]
  }

    # Allow RDP
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["218.2.208.75/32", "18.162.103.100/32", "36.152.113.203/32", "58.212.197.96/32", aws_vpc.my-lab-vpc.cidr_block]
  }

    # Allow TLS
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["218.2.208.75/32", "18.162.103.100/32", "36.152.113.203/32", "58.212.197.96/32", aws_vpc.my-lab-vpc.cidr_block]
  }

    # Allow http
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["218.2.208.75/32", "18.162.103.100/32", "36.152.113.203/32", "58.212.197.96/32", aws_vpc.my-lab-vpc.cidr_block]
  }

    # Allow inbound dsa ports from anywhere (c1ws dsm ip addresses?)
  ingress {
    from_port   = 4118
    to_port     = 4122
    protocol    = "tcp"
    cidr_blocks = ["54.221.196.0/24"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "cncorelab-sg"
  }
}



# 7. Create userdata parameter with windows and linux dsa installation/activation script 

data "template_file" "windowsps" {

  template = <<-EOF
              <powershell>
              #requires -version 4.0

              # PowerShell 4 or up is required to run this script
              # This script detects platform and architecture.  It then downloads and installs the relevant Deep Security Agent package

              if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
                Write-Warning "You are not running as an Administrator. Please try again with admin privileges."
                exit 1
              }

              $managerUrl="https://app.deepsecurity.trendmicro.com:443/"

              $env:LogPath = "$env:appdata\Trend Micro\Deep Security Agent\installer"
              New-Item -path $env:LogPath -type directory
              Start-Transcript -path "$env:LogPath\dsa_deploy.log" -append

              echo "$(Get-Date -format T) - DSA download started"
              if ( [intptr]::Size -eq 8 ) { 
                $sourceUrl=-join($managerUrl, "software/agent/Windows/x86_64/agent.msi") }
              else {
                $sourceUrl=-join($managerUrl, "software/agent/Windows/i386/agent.msi") }
              echo "$(Get-Date -format T) - Download Deep Security Agent Package" $sourceUrl

              $ACTIVATIONURL="dsm://agents.deepsecurity.trendmicro.com:443/"

              $WebClient = New-Object System.Net.WebClient

              # Add agent version control info
              $WebClient.Headers.Add("Agent-Version-Control", "on")
              $WebClient.QueryString.Add("tenantID", "91946")
              $WebClient.QueryString.Add("windowsVersion", (Get-CimInstance Win32_OperatingSystem).Version)
              $WebClient.QueryString.Add("windowsProductType", (Get-CimInstance Win32_OperatingSystem).ProductType)

              [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;

              Try
              {
                  $WebClient.DownloadFile($sourceUrl,  "$env:temp\agent.msi")
              } Catch [System.Net.WebException]
              {
                    echo " Please check that your Deep Security Manager TLS certificate is signed by a trusted root certificate authority."
                    exit 2;
              }

              if ( (Get-Item "$env:temp\agent.msi").length -eq 0 ) {
                  echo "Failed to download the Deep Security Agent. Please check if the package is imported into the Deep Security Manager. "
              exit 1
              }
              echo "$(Get-Date -format T) - Downloaded File Size:" (Get-Item "$env:temp\agent.msi").length

              echo "$(Get-Date -format T) - DSA install started"
              echo "$(Get-Date -format T) - Installer Exit Code:" (Start-Process -FilePath msiexec -ArgumentList "/i $env:temp\agent.msi /qn ADDLOCAL=ALL /l*v `"$env:LogPath\dsa_install.log`"" -Wait -PassThru).ExitCode 
              echo "$(Get-Date -format T) - DSA activation started"

              Start-Sleep -s 50
              & $Env:ProgramFiles"\Trend Micro\Deep Security Agent\dsa_control" -r
              & $Env:ProgramFiles"\Trend Micro\Deep Security Agent\dsa_control" -a $ACTIVATIONURL "tenantID:6473E0CB-D7B1-B456-3227-80CF57C7F419" "token:FAD936FC-62BF-CCBC-11C4-29508A2D9878" "policyid:4"
              #& $Env:ProgramFiles"\Trend Micro\Deep Security Agent\dsa_control" -a dsm://agents.deepsecurity.trendmicro.com:443/ "tenantID:6473E0CB-D7B1-B456-3227-80CF57C7F419" "token:FAD936FC-62BF-CCBC-11C4-29508A2D9878" "policyid:4"
              Stop-Transcript
              echo "$(Get-Date -format T) - DSA Deployment Finished"
              </powershell>
            EOF
}


data "template_file" "linuxshell" {

   template = <<-EOF
                #!/bin/bash

                ACTIVATIONURL='dsm://agents.deepsecurity.trendmicro.com:443/'
                MANAGERURL='https://app.deepsecurity.trendmicro.com:443'
                CURLOPTIONS='--silent --tlsv1.2'
                linuxPlatform='';
                isRPM='';

                if [[ $(/usr/bin/id -u) -ne 0 ]]; then
                    echo You are not running as the root user.  Please try again with root privileges.;
                    logger -t You are not running as the root user.  Please try again with root privileges.;
                    exit 1;
                fi;

                if ! type curl >/dev/null 2>&1; then
                    echo "Please install CURL before running this script."
                    logger -t Please install CURL before running this script
                    exit 1
                fi

                CURLOUT=$(eval curl $MANAGERURL/software/deploymentscript/platform/linuxdetectscriptv1/ -o /tmp/PlatformDetection $CURLOPTIONS;)
                err=$?
                if [[ $err -eq 60 ]]; then
                    echo "TLS certificate validation for the agent package download has failed. Please check that your Deep Security Manager TLS certificate is signed by a trusted root certificate authority. For more information, search for \"deployment scripts\" in the Deep Security Help Center."
                    logger -t TLS certificate validation for the agent package download has failed. Please check that your Deep Security Manager TLS certificate is signed by a trusted root certificate authority. For more information, search for \"deployment scripts\" in the Deep Security Help Center.
                    exit 1;
                fi

                if [ -s /tmp/PlatformDetection ]; then
                    . /tmp/PlatformDetection
                else
                    echo "Failed to download the agent installation support script."
                    logger -t Failed to download the Deep Security Agent installation support script
                    exit 1
                fi

                platform_detect
                if [[ -z "$linuxPlatform" ]] || [[ -z "$isRPM" ]]; then
                    echo Unsupported platform is detected
                    logger -t Unsupported platform is detected
                    exit 1
                fi

                echo Downloading agent package...
                if [[ $isRPM == 1 ]]; then package='agent.rpm'
                    else package='agent.deb'
                fi
                curl -H "Agent-Version-Control: on" $MANAGERURL/software/agent/$runningPlatform$majorVersion/$archType/$package?tenantID=91946 -o /tmp/$package $CURLOPTIONS

                echo Installing agent package...
                rc=1
                if [[ $isRPM == 1 && -s /tmp/agent.rpm ]]; then
                    rpm -ihv /tmp/agent.rpm
                    rc=$?
                elif [[ -s /tmp/agent.deb ]]; then
                    dpkg -i /tmp/agent.deb
                    rc=$?
                else
                    echo Failed to download the agent package. Please make sure the package is imported in the Deep Security Manager
                    logger -t Failed to download the agent package. Please make sure the package is imported in the Deep Security Manager
                    exit 1
                fi
                if [[ $rc != 0 ]]; then
                    echo Failed to install the agent package
                    logger -t Failed to install the agent package
                    exit 1
                fi

                echo Install the agent package successfully

                sleep 15
                /opt/ds_agent/dsa_control -r
                /opt/ds_agent/dsa_control -a $ACTIVATIONURL "tenantID:6473E0CB-D7B1-B456-3227-80CF57C7F419" "token:FAD936FC-62BF-CCBC-11C4-29508A2D9878" "policyid:8"
                # /opt/ds_agent/dsa_control -a dsm://agents.deepsecurity.trendmicro.com:443/ "tenantID:6473E0CB-D7B1-B456-3227-80CF57C7F419" "token:FAD936FC-62BF-CCBC-11C4-29508A2D9878" "policyid:8"
              EOF
}

# 8. Create Windows and Linux server and install/activate dsa


resource "aws_instance" "dsa_linux" {
  ami = "ami-09558250a3419e7d0"
  instance_type = "t2.micro"
  key_name = "AWS_Key_Felix"
  subnet_id = aws_subnet.public-subnet-1.id
  vpc_security_group_ids = [aws_security_group.cncorelab-sg.id]
  associate_public_ip_address = true

  user_data = data.template_file.linuxshell.rendered

  tags = {
    Name = "dsa-awslinux-felix"
  }
}


resource "aws_instance" "dsa_windows" {
  count = 1
  ami = "ami-07e4bc48db918b14f"
  instance_type = "t2.micro"
  key_name = "AWS_Key_Felix"
  subnet_id = aws_subnet.public-subnet-2.id
  vpc_security_group_ids = [aws_security_group.cncorelab-sg.id]
  associate_public_ip_address = true

  user_data = data.template_file.windowsps.rendered


  # get password of windows
  get_password_data = true

  tags = {
    Name = "dsa-awswindows-felix"
  }
}



# 9. output the ip address/dns name of windows and linux server

output "dsa_windows" {
     value = [
       for i in aws_instance.dsa_windows: i.public_ip
     ]
}

output "Administrator_Password" {
  value = [
    for i in aws_instance.dsa_windows : rsadecrypt(i.password_data, file("AWS_Key_Felix.pem"))
  ]
}

output "dsa_linux" {
     value = aws_instance.dsa_linux.public_ip
}