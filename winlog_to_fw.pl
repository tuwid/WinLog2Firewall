#!/usr/bin/perl

# open file 		-
# get file content 		-
# filter content with regex -
# get list of IPs - 
# filter duplicate list of IPs - 
# execute netsh command  
## optional flush the list of IPs in a txt file 
## optional set a whitelist (just in case)

my @lines;
my @ip_to_ban;
my @filtered_ips;

sub uniq_ips {
    my %seen;
    grep !$seen{$_}++, @_;
}

open FILE,'<C:\assp\logs\maillog.txt' or die "Could not open file \n";

while (<FILE>) {
  # print join('|',@row)."\n";
  #@lines = <FILE>;
  chomp(@lines = <FILE>);
}

close(FILE);


#print join('',@lines);
foreach my $line (@lines){
	#print $line;
	if($line =~ m/(.*) (.*) (.*) \[SMTP Error\] 504 Invalid Username or Password/g){
		push(@ip_to_ban, $3);
	}
}

print scalar(@ip_to_ban)." failed logins \n";
@filtered_ips = uniq_ips(@ip_to_ban);
print scalar(@filtered_ips)." unique ips to ban \n";

open FILE,'>>C:\ASSP_IPautoban\blocked_ips.txt' or die "Could not open blocked file \n";
	print FILE join("\n",@filtered_ips)."\n";
close(FILE);


open FILE,'<C:\ASSP_IPautoban\blocked_ips.txt' or die "Could not open blocked file \n";

while (<FILE>) {
  # print join('|',@row)."\n";
  chomp(@blocked_lines_f = <FILE>);
}

close(FILE);

my @blocked_l;
foreach my $l (@blocked_lines_f){
	chomp($l);
	push(@blocked_l,"$l");
}

my @total_ips = uniq_ips(@blocked_l);

my $ip_to_block = join(',',@total_ips);

open FILE,'>C:\ASSP_IPautoban\blocked_ips.txt' or die "Could not open blocked file \n";
  # print join('|',@row)."\n";
	print FILE join("\n",@total_ips)."\n";
close(FILE);

my $block_count = 0;
print "Deleting rules..\n";
for(my $i = 0;$i <= 10; $i++){
	system("netsh advfirewall firewall delete rule name=\"Block_$i\"");
	#print netsh advfirewall firewall delete rule name=\"Block_$i\"
}

my @temp_ips;
for(my $j = 0; $j< scalar(@total_ips);$j++){
	if($j % 200 == 0 and $j>0){
		print "Adding block $block_count with ".scalar(@temp_ips)." IPs\n";
		my $remote_ips = join(',',@temp_ips);
		#print $remote_ips."\n";
		system("netsh advfirewall firewall add rule name=\"Block_$block_count\" protocol=any dir=in action=block remoteip=\"$remote_ips\"");
		$block_count++;
		@temp_ips = ();
	}
	push(@temp_ips,$total_ips[$j]);
}
if(scalar(@temp_ips) > 0){
		print "Adding block $block_count with ".scalar(@temp_ips)." IPs\n";
		my $remote_ips = join(',',@temp_ips);
		system("netsh advfirewall firewall add rule name=\"Block_$block_count\" protocol=any dir=in action=block remoteip=\"$remote_ips\"");
		$block_count++;
		#netsh advfirewall firewall add rule name=\"Block_$i\" protocol=any dir=in action=block remoteip=$remote_ips
		@temp_ips = ();
}

#netsh advfirewall firewall add rule name="Blockit" protocol=any dir=in action=block remoteip=%%i
#system("netsh.exe advfirewall firewall set rule name=\"IP Block list\" new remoteip=\"$ip_to_block\"");
#system("netsh.exe advfirewall firewall set rule name=\"IP Block list\" new remoteip=\"$ip_to_block\"");
#system("netsh.exe advfirewall firewall set rule name=\"IP Block list\" new remoteip=\"$ip_to_block\"");
#print $ip_to_block;
#print "netsh.exe advfirewall firewall set rule name=\"Block External IPs\" new remoteip=\"$ip_to_block\"\n";
