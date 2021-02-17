public class Main {

	public static void main(String[] args) throws Exception {
//		String inputFilePath = args[0];
//		String outDiractory = args[1]; 
//		String timeOutString = args[2];
//		long timeout = Long.valueOf(timeOutString);
		
		String inputFilePath = "C:\\temp\\Pcap_Split\\sampels\\sample_1.pcap";
		String outDiractory = "C:\\temp\\Pcap_Split\\sampels\\output"; 
		long timeOut = (long) 4000 ;

		Handelr pcaphandler = new Handelr(inputFilePath, outDiractory); 
		pcaphandler.analyze(timeOut);
		 
	}
}
