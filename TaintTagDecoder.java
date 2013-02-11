import java.util.Vector;
import java.lang.Integer;

public class TaintTagDecoder {
	
	public static final int LOW_PART_BITS = 20;
	public static final int HIGH_PART_BITS = 4;
	public static final int PERIOD = LOW_PART_BITS * HIGH_PART_BITS;
	public static final int LOW_PART_MASK	= 0x000FFFFF;
	public static final int HIGH_PART_MASK = 0x00F00000;
	public static final int CODE_MASK 		= 0x00FFFFFF;

	public static final int TAINT_CONTROL_FLOW	= 0x80000000;
    public static final int TAINT_LOCATION_GPS  = 0x40000000;
    public static final int TAINT_LOCATION_NET  = 0x20000000;
    public static final int TAINT_ACCELEROMETER = 0x10000000;
	public static final int TAINT_MAGNETIC_FIELD= 0x08000000;
	public static final int TAINT_GYROSCOPE		= 0x04000000;
	public static final int TAINT_LIGHT			= 0x02000000;
	public static final int TAINT_MIC           = 0x01000000;
 
	
	public static int encode(int x) {
		x = x % PERIOD;
		int low = x % LOW_PART_BITS;
		int high = x / LOW_PART_BITS;
		int lowCode = 1 << low;
		int highCode = 1 << high;
		
		return ((highCode << LOW_PART_BITS) | lowCode);
	}
	
	private static int[] bitsOn(int x) {
		Vector<Integer> v = new Vector<Integer>();
		
		int l = 0;
		while (x > 0) {
			if ((x & 1) != 0) v.add(l);
			l++;
			x >>= 1;
		}
		
		int ret[] = new int[v.size()];
		for (int i = 0; i < v.size(); i++)
			ret[i] = v.get(i);
		
		return ret;
	}
	
	public static int[] decode(int x) {
		
		x &= CODE_MASK;
		
		int lowCode = x & LOW_PART_MASK;
		int highCode = (x & HIGH_PART_MASK) >> LOW_PART_BITS;
		
		int[] lowBits = bitsOn(lowCode);
		int[] highBits = bitsOn(highCode);
		
		int[] ret = new int[lowBits.length * highBits.length];
		for (int i = 0; i < highBits.length; i++)
			for (int j = 0; j < lowBits.length; j++)
				ret[i * lowBits.length + j] = highBits[i] * LOW_PART_BITS + lowBits[j];
		
		return ret;
	}
/*
	public static int hexToDec(String s) {
		s = s.toLowerCase();
		int val = 0;
		for (int i = 0; i < s.length; i++) {
			val *= 16;
			if (Charecter.isDigit(s[0]))
				val += (s[i] - '0');
			else
				val += (s[0] - 'a' + 10);
		}
		return val;
	}
*/	
	public static void main(String[] args) {

		if (args.length < 1) {
			System.out.println("java TaintTagDecoder <tag>");
			return;
		}

		int input;
		if (args[0].startsWith("0x"))
			input = Integer.parseInt(args[0].substring(2), 16);
		else
			input = Integer.parseInt(args[0]);

		if ((input & TAINT_CONTROL_FLOW) > 0)
			System.out.println("Tainted by control flow");
		if ((input & TAINT_LOCATION_GPS) > 0)
			System.out.println("GPS Location");
		if ((input & TAINT_LOCATION_NET) > 0)
			System.out.println("Network Location");
		if ((input & TAINT_ACCELEROMETER) > 0)
			System.out.println("Accelerometer");
		if ((input & TAINT_MAGNETIC_FIELD) > 0)
			System.out.println("Magnetic Field");
		if ((input & TAINT_GYROSCOPE) > 0)
			System.out.println("Gyroscope");
		if ((input & TAINT_LIGHT) > 0)
			System.out.println("Light");
		if ((input & TAINT_MIC) > 0)
			System.out.println("Microphone");

		int[] tags = decode(input);
		System.out.println("Taint index:");
		for (int i = 0; i < tags.length; i++)
			System.out.println(tags[i]);
	}
}
