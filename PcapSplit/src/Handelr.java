import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

public class Handelr {

	private File pcapFile;
	private FileInputStream fi;
	private DataInputStream di ;
	private DataOutputStream csvOs;
	private ByteBuffer pcapByteBuffer;

	private byte [] pcapHeader;
	private boolean isBigIndean;
	private String outDiractory;
	private Map<String, Session> mapOfSessions;
	private Session sessionNotProcesset;
	private int sessionCounter = 0;
	private long timeOut;

	public Handelr(String inputFilePath ,String outDiractory) throws Exception {

		pcapFile = new File(inputFilePath);
		if (! pcapFile.isFile() || ! pcapFile.canRead()){
			throw new Exception("file not found or the file cannot be read ");
		}
		//TODO add file check

		fi = new FileInputStream(pcapFile);
		di = new DataInputStream(fi);
		pcapHeader = new byte[24];

		this.outDiractory = outDiractory;

		mapOfSessions = new HashMap<String, Session>();
	}

	public void analyze(long timeOut) throws Exception {
		this.timeOut = timeOut;
		di.read(pcapHeader);		
		sessionCounter++;
		sessionNotProcesset = new Session(outDiractory,pcapHeader,sessionCounter);
		pcapByteBuffer = ByteBuffer.wrap(pcapHeader);
		int magic = pcapByteBuffer.getInt();

		// get the type if its BIG_ENDIAN or LITTLE_ENDIAN
		if(magic == 0xa1b2c3d4) {
			isBigIndean =true;
		}else if(magic == 0xd4c3b2a1) {
			isBigIndean =false;
		}else {
			throw new Exception("NOT A PCAP FILE");
		}

		setByteOrder(pcapByteBuffer);
		int linkProtocol = pcapByteBuffer.getInt(20); // go to the protocol specification 

		//if its not 0x1 its not ETHERNET II
		if(linkProtocol != 0x1) {
			throw new Exception("The protocol is not ETHERNET II");
		}
		byte [] packetHeader = new byte[16];
		byte [] packetData = new byte[67000];
		//create csv file
		createCSV();
		while(di.available()>0) {
			//check if the header is full
			if(di.available() < packetHeader.length) {
				break;
			}
			di.read(packetHeader);
			pcapByteBuffer = ByteBuffer.wrap(packetHeader);
			setByteOrder(pcapByteBuffer);
			int dataSize = pcapByteBuffer.getInt(8);
			if(di.available() < dataSize) {
				break;
			}
			di.read(packetData,0,dataSize);
			handlePacket(packetHeader,packetData,isBigIndean);
		}

		for(Map.Entry<String, Session> entry: mapOfSessions.entrySet()) {
			Session session = entry.getValue();
			if(!session.isClosed()) {
				printSessionToCSV(session);
				session.close(); 
			}
		}
		di.close();
		csvOs.close();
	} 

	private void handlePacket(byte[] packetHeader, byte[] packetData, boolean isBigIndean) throws Exception {
		Packet packet = new Packet(packetHeader,packetData,isBigIndean);
		if(packet.isAnalyzeable()) {
			String key1 = packet.getPacketKey1();
			String key2 = packet.getPacketKey2();
			Instant packetTime = packet.getTimeStamp();
			Session session = mapOfSessions.get(key1);
			if(session == null ) {
				try {
					sessionCounter++;
					session = new Session(outDiractory, pcapHeader,sessionCounter);
					session.addPacket(packet);
				} catch (IOException e) {
					System.err.println("problem in creating new session");
				}
				mapOfSessions.put(key1, session);
				mapOfSessions.put(key2, session);
			}else if(packetTime.minusMillis(timeOut).isAfter(session.getLestPacketTime()) ){

				printSessionToCSV(session);
				session.close();
				sessionCounter++;
				session = new Session(outDiractory, pcapHeader,sessionCounter);
				session.addPacket(packet);
				mapOfSessions.replace(key1, session);
				mapOfSessions.replace(key2, session);
			}
			else{
				session.addPacket(packet);
			}
		}else {
			sessionNotProcesset.addPacket(packet);
		}
	}

	private void setByteOrder(ByteBuffer bb) {
		if(isBigIndean) {
			bb.order(ByteOrder.BIG_ENDIAN);
		}else {
			bb.order(ByteOrder.LITTLE_ENDIAN);
		}
	}

	private void createCSV() throws Exception {
		String csvheadLine = String.format("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s","file-number", "src-ip","src-port","dst-ip","dst-port"," ip-protocol",
				"start-time","end-time","number-of-packets","number-of-bytes-in-session\n");
		File directory = new File(outDiractory);
		if (! directory.exists()){
			directory.mkdir();
		}
		File csvFile = new File(outDiractory+"\\"+"Session_Analyze.csv");
		FileOutputStream csvFo = new FileOutputStream(csvFile);
		csvOs = new DataOutputStream(csvFo);
		csvOs.writeChars(csvheadLine);
	}
	private void printSessionToCSV(Session session) throws Exception {
		String startTime = session.getSessionStartTime().toString();
		String endTime = session.getLestPacketTime().toString();
		String line = String.format("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",session.getFileNumber(), session.getSrcIp(),session.getSrcPort(),
				session.getDstIp(),session.getDstPort(),session.getProtocol(),startTime,endTime,session.getNumOfPacketsInSession(),
				session.getNumOfByetsInSession());
		csvOs.writeChars(line);
	}

}
