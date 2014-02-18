#-----------------------------------------------------------
# landesk_slm.pl
#   LANDESK Software License Monitor Log Parser
#
# Change history
#   20130425 - Initial version
#
# References
#
# Copyright
#   2013 - Justin Prosco <justin.prosco@mandiant.com>
#-----------------------------------------------------------
package landesk_slm;
use strict;
use Parse::Win32Registry qw(iso8601);
use Parse::Win32Registry qw(unpack_windows_time);

my %config = (
    hive          => "Software",
    osmask        => 127,
    hasShortDescr => 1,
    hasDescr      => 0,
    hasRefs       => 0,
    version       => 20130425
);

sub getConfig       {return %config;}
sub getShortDescr   {return "LANDesk Registry Parser";}
sub getDescr        {return "Parses LANDesk Software Licensing Monitor from SOFTWARE hive";}
sub getRefs         {return "N/A";}
sub getHive         {return $config{hive};}
sub getVersion      {return $config{version};}

my $VERSION = getVersion();

sub pluginmain { 
  my $class = shift; 
  my $hive = shift; 
  my @keys = ("LANDesk\\ManagementSuite\\WinClient\\SoftwareMonitoring\\MonitorLog",
              "Wow6432Node\\LANDesk\\ManagementSuite\\WinClient\\SoftwareMonitoring\\MonitorLog");
              
  ::logMsg("Launching landesk_slm v".$VERSION); 
  ::rptMsg("landesk_slm v".$VERSION." (".getShortDescr().")"); 
  my $reg = Parse::Win32Registry->new($hive); 
  my $root_key = $reg->get_root_key; 

  foreach my $key_path (@keys) {
    my $key;
    if ($key = $root_key->get_subkey($key_path)) {
        ::rptMsg($key_path);
        my @subkeys = $key->get_list_of_subkeys();
        if (scalar(@subkeys) > 0) {
            foreach my $s (@subkeys) {
                eval {
                    my $path = $s->get_name();
                    my $current_duration = unpack("V", $s->get_value("Current Duration")->get_data()) / 10000000;
                    my $current_user = $s->get_value("Current User")->get_data();
                    my $first_started = iso8601(unpack_windows_time($s->get_value("First Started")->get_data()));
                    my $last_duration = unpack("V", $s->get_value("Last Duration")->get_data()) / 10000000;
                    my $last_started = iso8601(unpack_windows_time($s->get_value("Last Started")->get_data()));
                    my $total_duration = unpack("V", $s->get_value("Total Duration")->get_data()) / 10000000;
                    my $total_runs = $s->get_value("Total Runs")->get_data();
                    
                    # print the LANDesk monitorlog entry
                    ::rptMsg($path);
                    ::rptMsg("\tCurrent Duration:\t" . $current_duration);
                    ::rptMsg("\tCurrent User:\t" . $current_user);
                    ::rptMsg("\tFirst Started:\t" . $first_started);
                    ::rptMsg("\tLast Duration:\t" . $last_duration);
                    ::rptMsg("\tLast Started:\t" . $last_started);
                    ::rptMsg("\tTotal Duration:\t" . $total_duration);
                    ::rptMsg("\tTotal Runs:\t" . $total_runs);
                }
            }
        }
        else {
            ::rptMsg($key_path . " does not have subkeys.");
        }
    }
    else {
		::rptMsg($key_path . " not found.");
	}
  }
}