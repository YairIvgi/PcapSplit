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
	
	public int getNumOfByetsInSession() {
		return numOfByetsInSession;
	}
	
	public int getNumOfPacketsInSession() {
		return numOfPacketsInSession;
	}
	
	public String getSrcIp() {
		return srcIp;
	}
	public String getDstIp() {
		return dstIp;
	}
	public String getSrcPort() {
		return srcPort;
	}
	public String getDstPort() {
		return dstPort;
	}
	public String getProtocol() {
		return protocol;
	}
	public int getFileNumber() {
		return fileNumber;
	}
	
}
