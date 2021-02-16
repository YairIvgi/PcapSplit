import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

public class Session {

	private File outputFile;
	private FileOutputStream fo;
	private DataOutputStream os;
	boolean isClosed;
	private long lestPacketTime;

	public Session(String outDiractory, byte[] pcapHeader,int counter) throws IOException {
		isClosed = false;

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
		os.write(packet.getHeader());
		int dataSize = packet.getDataSize();
		os.write(packet.getData(),0,dataSize);
	}
	public boolean isClosed() {
		return isClosed;
	}
	public void close() throws IOException {
		os.close();
		isClosed = true;
	}









}
