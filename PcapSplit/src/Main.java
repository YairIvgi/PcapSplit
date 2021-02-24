public class Main {

	public static void main(String[] args) throws Exception {
		//		String inputFilePath = args[0];
		//		String outDiractory = args[1]; 
		//		String timeOutString = args[2];
		//		long timeout = Long.valueOf(timeOutString);

		//arbitrary file path - used for tests
		String inputFilePath = "C:\\temp\\Pcap_Split\\samples\\sample_1.pcap";
		String outDiractory = "C:\\temp\\Pcap_Split\\samples\\sample_1"; 

		//time out is milliseconds
		long timeOut = (long) 4000 ;

		Handler pcaphandler = new Handler(inputFilePath, outDiractory); 
		pcaphandler.analyze(timeOut);
		pcaphandler.close();

	}
}
