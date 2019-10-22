import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Scanner;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

public class Sniffer 
{
	private boolean prom;
	private int outputMethod;
	private String filter="";
	private String string;
	private String fileName;

	private ArrayList<String> stringList = new ArrayList<String>();
	private static int packetCount = 0;
	
	public Sniffer()
	{
		init();
	}
	
	private void init()
	{
		List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs
		StringBuilder errbuf = new StringBuilder(); // For any error msgs
		
		menu();
	
		/***************************************************************************
		 * First get a list of devices on this system
		 **************************************************************************/
		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s", errbuf
			    .toString());
			return;
		}
	
		System.out.println("Network devices found:");
	
		int i = 0;
		for (PcapIf device : alldevs) {
			String description =
			    (device.getDescription() != null) ? device.getDescription()
			        : "No description available";
			System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
		}
		
		System.out.println("What device do you want to use?");
		Scanner devKb = new Scanner(System.in);
		int dev = devKb.nextInt();
		devKb.nextLine();
		//devKb.close();
		PcapIf device = alldevs.get(dev); // We know we have atleast 1 device
		
		System.out
		    .printf("\nUsing '%s':\n",
		        (device.getDescription() != null) ? device.getDescription()
		            : device.getName());
	
		
		int snaplen = 64 * 1024;           
		int flags;
		if(this.prom)
			flags = Pcap.MODE_PROMISCUOUS; // capture all packets
		else
			flags = Pcap.MODE_NON_PROMISCUOUS; //capture packets only addressed to you?
		
		int timeout = 10 * 1000;           // 10 seconds in millis
		
		
		Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
		
		if (pcap == null) {
			System.err.printf("Error while opening device for capture: "
			    + errbuf.toString());
			return;
		}
				
		PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>()
		{
			public  void nextPacket(PcapPacket packet, String user) 
			{
				packetCount ++;
				Tcp tcp = new Tcp();
				Udp udp = new Udp();
				Ip4 ip = new Ip4();
				Ip6 ip6= new Ip6();
				if(packet.hasHeader(ip)) //if the packet has an ip and tcp packet
				{
					user = "IPv4";
				}
				if(packet.hasHeader(ip6))
				{
					user = "IPv6";
				}
				if(packet.hasHeader(tcp))
				{
					if(tcp.source()==20||tcp.source()==21)
						user="FTP";
					if(tcp.source()==80)
						user="HTTP";
					else if(tcp.source()==443)
						user="HTTPS";
					else user="TCP";
				}
				
				if(packet.hasHeader(udp)) //if the packet header is udp
				{
					if(udp.source()==67||udp.source()==68)
						user="DHCP";
					else
						user="UDP";
				}
				
				StringBuilder str = new StringBuilder();
				packet.getUTF8String(0, str,packet.getTotalSize());
				
				if(outputMethod==1)
				{
					if(user.toLowerCase().compareTo(filter.toLowerCase())==0||filter.compareTo("")==0)
					{
						System.out.printf("Received packet #%d at %s caplen=%-4d len=%-4d %s\n",
								packetCount,
							    new Date(packet.getCaptureHeader().timestampInMillis()), 
							    packet.getCaptureHeader().caplen(),  // Length actually captured
							    packet.getCaptureHeader().wirelen(), // Original length 
							    user);
					}
				}
				else 
				{
					string = new String();
					if(user.toLowerCase().compareTo(filter.toLowerCase())==0||filter.compareTo("")==0)
					{
						string = "Received packet #"+packetCount+" at "+new Date(packet.getCaptureHeader().timestampInMillis()).toString()+" caplen="+packet.getCaptureHeader().caplen()+" len="+packet.getCaptureHeader().wirelen()+" "+user+"\r\n";
						stringList.add(string);
					}
				}

			}
		};
	
		//packet capturing
		Scanner kb =  new Scanner(System.in);
		System.out.println("How many packets would you like to capture?");
		int max=kb.nextInt();
		System.out.println("Capturing packets, please wait.....");
			

		pcap.loop(max,jpacketHandler, " ");
		if(outputMethod == 2)
		{
			System.out.println("Enter a filename including your file extension (ex: .txt):");
			kb = new Scanner(System.in);
			fileName = kb.nextLine();
			fileOutput(string);
		}
		pcap.close();
		
	}
	
	private void menu()
	{
		Scanner kb = new Scanner(System.in);
		Scanner kb2 = new Scanner(System.in);
		System.out.println("**********Main Menu**********");
		System.out.println("Do you want to use promiscuous mode? (Y/N)");
		String promString = kb.nextLine();
		
		if(promString.compareTo("Y")==0||promString.compareTo("y")==0)
			this.prom = true;
		else
			this.prom = false;
		
		System.out.println("Do you want to print to the console or a file? (1,2)");
		int choice = kb2.nextInt();
		if(choice==1||choice==2)
			this.outputMethod= choice;
		else
		{
			while(choice!=1||choice!=2) {
			System.out.println("Please enter 1 for console printing or 2 for file printing");
			choice = kb2.nextInt();
			}
		}
		
		System.out.println("Would you like to filter to the following protocols?");
		System.out.println("TCP, UDP, HTTP, HTTPS, FTP, IPv4/6, and DHCP");
		System.out.println("Type your answer exactly:");
		this.filter = kb.nextLine();
		
		if(filter.compareTo("All")==0||filter.compareTo("all")==0)
			filter="";
	}
	
	private void fileOutput(String string)
	{
		File file = new File(fileName);
		try 
		{
			FileWriter writer = new FileWriter(file);
			for(String s : stringList)
				writer.write(s);
			writer.close();
		} 
		catch (FileNotFoundException e) 
		{
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
