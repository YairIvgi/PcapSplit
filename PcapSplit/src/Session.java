import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.time.Instant;
 
public class Session {

	private File outputFile;
	private FileOutputStream fo;
	private DataOutputStream os;
	boolean isClosed;
	private Instant lestPacketTime;
	private Instant sessionStartTime;
	private int numOfPacketsInSession;
	private int numOfByetsInSession;

	private String srcIp;
	private String dstIp;
	private String srcPort;
	private String dstPort;
	private String protocol;
	private int fileNumber;

	//Constructor of session , open new pcap file 
	public Session(String outDiractory, byte[] pcapHeader,int counter) throws IOException {
		isClosed = false;
		sessionStartTime = null; 
		fileNumber = counter;
		File directory = new File(outDiractory);
		if (! directory.exists()){
			directory.mkdir();
		}
		outputFile = new File(outDiractory+"\\"+counter+".pcap");
		fo = new FileOutputStream(outputFile);
		os = new DataOutputStream(fo);
		os.write(pcapHeader);
	}

	//method to add packet to the session
	public void addPacket(Packet packet) throws IOException {
		if(sessionStartTime == null) {
			sessionStartTime = packet.getTimeStamp();
			srcIp = packet.getSrcIp();
			dstIp = packet.getDstIp();
			srcPort = packet.getSrcPort();
			dstPort = packet.getDstPort();
			protocol = packet.getProtocol();
		}
		os.write(packet.getHeader());
		int dataSize = packet.getDataSize();
		os.write(packet.getData(),0,dataSize);
		lestPacketTime = packet.getTimeStamp();
		numOfPacketsInSession++;
		numOfByetsInSession+=dataSize;
	}

	public boolean isClosed() {
		return isClosed;
	}
	
	public void close() throws IOException {
		os.close();
		isClosed = true;
	}

	public Instant getLestPacketTime() {
		return lestPacketTime;
	}

	public Instant getSessionStartTime() {
		return sessionStartTime;
	}
	
	public String getValues() {
		String startTime = sessionStartTime.toString();
		String endTime = lestPacketTime.toString();
		String line = String.format("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",fileNumber,srcIp,srcPort,
				dstIp,dstPort,protocol,startTime,endTime,numOfPacketsInSession,numOfByetsInSession);
		return line;
	}
}
