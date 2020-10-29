import java.awt.Desktop;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Scanner;
// ��ǻ�Ͱ��к� 201658109 �赿��

// Protocol �м�
public class Protocol {
	public static String r = "";

	// Ethernet Format �м�
	public static String ethernet(String Format) {

		// �Էµ� Format ���
		System.out.println("Ethernet Frame" + Format);
		r += "Ethernet Frame" + Format + "<br>";

		// Format�� ����� �⺻���� �������� ���Ұ�� --> ����ó��
		if (Format.length() < 28) {
			System.out.println("�ٽ� ���� �Է����ּ���!");
			r += "�ٽ� ���� �Է����ּ���!<br>";
			return r;
		} else {

			// Ethernet Header�� ������ �迭
			String[] EthernetFormat = new String[28];

			// Ethernet Header�� ���� �ϳ��� �и�
			for (int i = 0; i < EthernetFormat.length; i++) {
				EthernetFormat[i] = Character.toString(Format.charAt(i));
			}

			// �����͸� ������ �迭
			String[] Destination_Address = new String[12]; // Destination Address�� ������ �迭
			String[] Source_Address = new String[12]; // Source Address�� ������ �迭

			// Ethernet Format�� Destination, Source Address�� �и�
			System.arraycopy(EthernetFormat, 0, Destination_Address, 0, 12);
			System.arraycopy(EthernetFormat, 12, Source_Address, 0, 12);

			// Ethernet Format ���
			System.out.println("1. Ethernet");
			r += "1. Ethernet<br>";

			// Destination Address ���
			System.out.print(" 1) Destination Address : ");
			r += " 1) Destination Address : ";
			for (int i = 0; i < Destination_Address.length; i++) {
				if (i % 2 == 1 && i != Destination_Address.length - 1) {
					System.out.print(Destination_Address[i]);
					System.out.print(":");
					r += Destination_Address[i] + ":";
				} else {
					System.out.print(Destination_Address[i]);
					r += Destination_Address[i];
				}
			}
			System.out.print(" / " + CheckData(Destination_Address));
			r += " / " + CheckData(Destination_Address);
			System.out.println();
			r += "<br>";

			// Source Address ���
			System.out.print(" 2) Source Address : ");
			r += " 2) Source Address : ";
			for (int i = 0; i < Source_Address.length; i++) {
				if (i % 2 == 1 && i != Source_Address.length - 1) {
					System.out.print(Source_Address[i]);
					r += Source_Address[i];
					System.out.print(":");
					r += ":";
				} else {
					System.out.print(Source_Address[i]);
					r += Source_Address[i];
				}
			}
			System.out.print(" / " + CheckData(Source_Address));
			System.out.println();
			r += " / " + CheckData(Source_Address) + "<br>";

			// �̴��� �����ӿ� �����Ͱ� �ִ� ���!
			if (Format.length() > 28) {
				// Length�� Type ����
				String analys = Format.substring(24, 28);
				int AN_10 = Integer.parseInt(analys, 16);

				// Length�� ���� �м�
				if (AN_10 < 1536) {
					// Length �м�
					System.out.print(" 3) Length : ");
					r += " 3) Length : ";

					String L = Format.substring(28, Format.length() - 8);
					System.out.println(L.length() / 2 + "byte");
					r += L.length() / 2 + "byte<br>";

					// Data �� Padding �м�
					System.out.println(" 4) Data and Padding : " + L);
					r += " 4) Data and Padding : " + L + "<br>";

					// FCS ����
					String FCS = Format.substring(Format.length() - 8, Format.length());
					System.out.println(" 5) FCS : " + FCS);
					r += " 5) FCS : " + FCS + "<br>";

				}
				// Type�� ���� �м�
				else if (AN_10 >= 1536) {
					// Type �м�
					System.out.print(" 3) Type : ");
					r += " 3) Type : ";
					String Type = Format.substring(24, 28);
					System.out.print(Type);
					r += Type;

					// Ethernet Frame���� Ethernet Header�� ������ �� Data and padding
					String DAP = Format.substring(28, Format.length());

					// Type �м�
					if (Protocol(Type).equals("IP")) {
						System.out.println(" / IP");
						r += " / IP<br>";
						System.out.println("2. IP");
						r += "2. IP<br>";
						ip(DAP);
					} else if (Protocol(Type).equals("ARP")) {
						System.out.println(" / ARP");
						r += " / ARP<br>";
						System.out.println("2. ARP");
						r += "2. ARP<br>";
						arp(DAP);
					} else if (Protocol(Type).equals("XNS IDP")) {
						System.out.println(" / XNS IDP");
						r += " / XNS IDP<br>";
					} else if (Protocol(Type).equals("X.25 PLP")) {
						System.out.println(" / X.25 PLP");
						r += " / X.25 PLP<br>";
					} else if (Protocol(Type).equals("RARP")) {
						System.out.println(" / RARP");
						r += " / RARP<br>";
					} else if (Protocol(Type).equals("NetwareIPX")) {
						System.out.println(" / NetwareIPX");
						r += " / NetwareIPX<br>";
					} else if (Protocol(Type).equals("NetBIOS")) {
						System.out.println(" / NetBIOS");
						r += " / NetBIOS<br>";
					} else if (Protocol(Type).equals("VLAN ID")) {
						System.out.println(" / VLAN ID");
						r += " / VLAN ID<br>";
					} else if (Protocol(Type).equals("IPv6")) {
						System.out.println(" / IPv6");
						r += " / IPv6<br>";
						System.out.println("2. IPv6");
						r += "2. Ipv6<br>";
						ip6(DAP);
					} else if (Protocol(Type).equals("MPLS")) {
						System.out.println(" / MPLS");
						r += " / MPLS<br>";
					} else if (Protocol(Type).equals("PPPoE Discovery Stage")) {
						System.out.println(" / PPPoE Discovery Stage");
						r += " / PPPoE Discovery Stage<br>";
					} else if (Protocol(Type).equals("PPPoE PPP Session Stage")) {
						System.out.println(" / PPPoE PPP Session Stage");
						r += " / PPPoE PPP Session Stage<br>";
					} else if (Protocol(Type).equals("IEEE 802.1x")) {
						System.out.println(" / IEEE 802.1x");
						r += " / IEEE 802.1x<br>";
					} else {
						System.out.println(" / �м��� �Ұ����� Type�Դϴ�.");
						r += " / �м��� �Ұ����� Type�Դϴ�.<br>";
					}
				}
			} else {
				System.out.println("�ش� �����ӿ��� ����� ������ �����Ͱ� �������� �ʽ��ϴ�.");
				r += "�ش� �����ӿ��� ����� ������ �����Ͱ� �������� �ʽ��ϴ�.<br>";
			}
			// �ʱ�ȭ
			String field = r;
			r = "";

			return field;

		}
	}

	// ipv6 �м�
	private static void ip6(String format) {
		// TODO Auto-generated method stub
		if (format.length() < 80) {
			System.out.println("�ٽ� ���� �Է����ּ���!");
			r += "�ٽ� ���� �Է����ּ���!<br>";
		} else {
			// ���� Ȯ��
			String version = format.substring(0, 1);
			System.out.println(" 1) version : " + version);
			r += " 1) version : " + version + "<br>";

			// Traffic Class �м�
			String TC = format.substring(1, 3);
			System.out.println(" 2) Traffic Class : " + TC);
			r += " 2) Traffic Class : " + TC + "<br>";

			// Flow Label
			String FL = format.substring(3, 8);
			System.out.println(" 3) Flow Label : " + FL);
			r += " 3) Flow Label : " + FL + "<br>";

			// Payload Length
			String PL = format.substring(8, 12);
			System.out.println(" 4) Payload Length : " + PL);
			r += " 4) Payload Length : " + PL + "<br>";

			// Next Header
			String NH = format.substring(12, 14);
			System.out.println(" 5) Next Header : " + NH);
			r += " 5) Next Header : " + NH + "<br>";

			// Hop limit
			String HL = format.substring(14, 16);
			System.out.println(" 6) Hop Limit : " + HL);
			r += " 6) Hop Limit : " + HL + "<br>";

			// Source Address
			String SA = format.substring(16, 48);
			System.out.println(" 7) Source Address : " + SA);
			r += " 7) Source Address : " + SA + "<br>";

			// Destination Address
			String DA = format.substring(48, 80);
			System.out.println(" 8) Destination Address : " + DA);
			r += " 8) Destination Address : " + DA + "<br>";

			// Ȯ����� �м�
			int PL_10 = Integer.parseInt(PL, 16);
			if (PL_10 > 0) {
				String HC = format.substring(80, format.length());
				System.out.println(" 9) Next Header Content : " + HC);
				r += " 9) Next Header Content : " + HC + "<br>";
			}
		}
	}

	// ������ ��� ��� Ȯ���ϱ�
	public static String CheckData(String[] code) {
		String broad = "ffffffffffff"; // ��ε�ĳ��Ʈ
		String result = "";
		String unknown = "000000000000"; // Unknown MAC

		if (Combine(code).equals(broad)) {
			result = "Broadcast";
		} else if (MulticastCheck(code).equals("Multicast")) {
			result = "Multicast";
		} else if (Combine(code).equals(unknown)) {
			result = "Unknown MAC";
		} else {
			result = "Unicast";
		}
		return result;
	}

	// String[] --> String : ���ڿ� �迭�� ���ڿ��� ��ȯ
	public static String Combine(String[] code) {
		String result = "";
		for (int i = 0; i < code.length; i++) {
			result = result + code[i];
		}
		return result;
	}

	// ��Ƽĳ��Ʈ�� Ȯ���ϱ� ���� �޼��� 1110���� �����ϸ� 224.0.0.0 ~ 239.255.255.255 ���̿� ������ Multicast
	public static String MulticastCheck(String[] code) {
		String hex[] = new String[6];
		String result = "";

		hex[0] = code[0] + code[1];
		hex[1] = code[2] + code[3];
		hex[2] = code[4] + code[5];

		int a = Integer.parseInt(hex[2], 16);
		if ((hex[0] + hex[1]).equals("1110")) {
			if (a >= 224 && a <= 239) {
				result = "Multicast";
			}
		}

		return result;
	}

	// Ip Format �м�
	public static void ip(String Format) {
		// Format�� ����� 1�� ���
		if (Format.length() < 40) {
			System.out.println("�ٽ� ���� �Է����ּ���!");
			r += "�ٽ� ���� �Է����ּ���!<br>";
		} else {
			String Ver = ""; // VER ��
			String HeaderLength = ""; // HeaderLength ��
			int HL = 0; // HeaderLength�� byte ��
			String ServiceType = ""; // ServiceType ��
			String TotalLength = ""; // TotalLength ��
			String Identification = ""; // Identification ��
			String Flags = ""; // Flags ��
			String Offset = ""; // Offset ��
			String TTL = ""; // TTL ��
			String Protocol = ""; // Protocol ��
			String Checksum = ""; // Checksum ��
			String SourceAddress = ""; // Source Address ��
			String DestinationAddress = ""; // Destination Address ��
			String protocol_type = ""; // protocol_type�� �޾Ƽ� ���� �������ݷ� �Ѿ�� ���� ��
			String Other_Frame = ""; // Tcp_Frame�� �޾Ƽ� TCP�޼��忡 ���� �Ŀ� �м��ϱ� ���� ��

			// Version ���ϱ�
			Ver = Character.toString(Format.charAt(0));
			System.out.println(" 1) Version : 0" + Ver);
			r += " 1) Version : 0" + Ver + "<br>";

			// Header Length 10���� ���ϱ�
			HeaderLength = Character.toString(Format.charAt(1));
			int HL_10 = Integer.parseInt(HeaderLength, 16);
			System.out.print(" 2) Header Length : " + HL_10 + " / ");
			r += " 2) Header Length : " + HL_10 + " / ";

			// Header Length ����Ʈ ���ϱ�
			HL = HL_10 * 4;
			System.out.print(HL + " byte : ");
			r += HL + " byte : ";

			// Option ǥ��
			if (HL_10 == 5) {
				System.out.println("NO-option");
				r += "NO-option<br>";
			} else {
				System.out.println("Has-option");
				r += "Has-option<br>";
			}

			// Service Type �� ���ϱ�
			ServiceType = Format.substring(2, 4);
			Service_Type(ServiceType);

			// Total Length �� ���ϱ�
			TotalLength = Format.substring(4, 8);
			System.out.print(" 4) Total Length : " + TotalLength + " / ");
			r += " 4) Total Length : " + TotalLength + " / ";

			// TotalLengthfmf 10������ ��ȯ
			int TL_10 = Integer.parseInt(TotalLength, 16);
			System.out.println(
					TL_10 + " bytes : " + (TL_10 - (int) Integer.parseInt(HeaderLength) * 4) + " bytes payload");
			r += TL_10 + " bytes : " + (TL_10 - (int) Integer.parseInt(HeaderLength) * 4) + " bytes payload<br>";

			// Identification �� ���ϱ�
			Identification = Format.substring(8, 12);
			System.out.print(" 5) Identification : " + Identification + " / ");
			r += " 5) Identification : " + Identification + " / ";

			// Service Type�� 10������ ��ȯ
			int identification_10 = Integer.parseInt(Identification, 16);
			System.out.println(identification_10);
			r += identification_10 + "<br>";

			// Flags �� ���ϱ�
			Flags = Character.toString(Format.charAt(12));
			flags(Flags);

			// Offset �� ���ϱ�
			Offset = Format.substring(13, 16);
			System.out.print(" 7) Offset : " + Offset + " / ");
			r += " 7) Offset : " + Offset + " / ";
			// offset ���� ���ϱ�
			int offset_stand = 0;
			if (TL_10 / 3 == 0) {
				offset_stand = TL_10 / 3;
			} else {
				offset_stand = TL_10 / 3 + 1;
			}

			int o_10 = Integer.parseInt(Offset, 16);
			if (o_10 >= 0 && o_10 < offset_stand) {
				System.out.println("First Fragment");
				r += "First Fragment<br>";
			} else if (o_10 >= offset_stand && o_10 < offset_stand * 2) {
				System.out.println("Second Fragment");
				r += "Second Fragment<br>";
			} else if (o_10 >= offset_stand * 2 && o_10 < offset_stand * 3) {
				System.out.println("Third Fragment");
				r += "Third Fragment<br>";
			} else {
				System.out.println();
				r += "<br>";
			}

			// TTL �� ���ϱ�
			TTL = Format.substring(16, 18);
			ttl(TTL);

			// Protocol �� ���ϱ�
			Protocol = Format.substring(18, 20);
			protocol(Protocol);

			// Checksum ���ϱ�
			Checksum = Format.substring(20, 24);
			System.out.println(" 10) Checksum : " + Checksum);
			r += " 10) Checksum : " + Checksum + "<br>";

			// Source Address ���ϱ�
			SourceAddress = Format.substring(24, 32);
			System.out.print(" 11) Source Address : " + SourceAddress + " / ");
			r += " 11) Source Address : " + SourceAddress + " / ";
			IP_16_10(SourceAddress);

			// Destination Address ���ϱ�
			DestinationAddress = Format.substring(32, 40);
			System.out.print(" 12) Destination Address : " + DestinationAddress + " / ");
			r += " 12) Destination Address : " + DestinationAddress + " / ";
			IP_16_10(DestinationAddress);

			// IP Header Options
			if (!(HL_10 == 5) && HL >= 22) {
				// Option �� ���ϱ�
				String Option = Format.substring(40, HL * 2);

				// option code type -- option�� ���� ���
				String OCT = Format.substring(40, 42);

				// option length -- option�� ���� ���
				String Ol = Format.substring(42, 44);

				// option data -- option�� ���� ���
				String Op = Format.substring(44, HL * 2);

				System.out.println(" 13) Option");
				r += " 13) Option<br>";

				System.out.println("  - Has " + (HL - 20) + " byte option : " + Option + " / " + ip_option(Option));
				r += "  - Has " + (HL - 20) + " byte option : " + Option + " / " + ip_option(Option) + "<br>";

				System.out.println("  - option code type : " + OCT);
				r += "  - option code type : " + OCT;

				// option code type 10���� ��ȯ
				int OCT_10 = Integer.parseInt(OCT, 16);

				// option code type 2���� ��ȯ
				String OCT_2 = Integer.toBinaryString(OCT_10);

				// OCT_2 �ڸ� ���߱�
				if (OCT_2.length() == 0) {
					OCT_2 = "00000000";
				} else if (OCT_2.length() == 1) {
					OCT_2 = "0000000" + OCT_2;
				} else if (OCT_2.length() == 2) {
					OCT_2 = "000000" + OCT_2;
				} else if (OCT_2.length() == 3) {
					OCT_2 = "00000" + OCT_2;
				} else if (OCT_2.length() == 4) {
					OCT_2 = "0000" + OCT_2;
				} else if (OCT_2.length() == 5) {
					OCT_2 = "000" + OCT_2;
				} else if (OCT_2.length() == 6) {
					OCT_2 = "00" + OCT_2;
				} else if (OCT_2.length() == 7) {
					OCT_2 = "0" + OCT_2;
				}

				// Option copy �м�
				String Option_Copy = OCT_2.substring(0, 1);
				System.out.println("  - copy : " + Option_Copy);
				r += "  - copy : " + Option_Copy + "<br>";

				// Option class �м�
				String Option_Class = OCT_2.substring(1, 3);
				System.out.println("  - class : " + Option_Class);
				r += "  - class : " + Option_Class + "<br>";

				// Option number �м�
				String Option_Number = OCT_2.substring(3, 8);
				System.out.println("  - number : " + Option_Number);
				r += "  - number : " + Option_Number + "<br>";

				// option length �м�
				int OL_10 = Integer.parseInt(Ol, 16);
				System.out.println("  - option length : " + Ol + " / " + OL_10 / 8 + " byte");
				r += "  - option length : " + Ol + " / " + OL_10 / 8 + " byte" + "<br>";

				// option data �м�
				System.out.println("  - option data : " + Op);
				r += "  - option data : " + Op + "<br>";

			}

			// IP��� ������ ��
			Other_Frame = Format.substring(HL_10 * 8, Format.length());

			// Protocol�� ���� �м��Ͽ� ���� ������ �м� ����
			protocol_type = protocol_finding(Protocol);
			if (protocol_type.equals("TCP")) {
				System.out.println("3. TCP");
				r += "3. TCP<br>";
				tcp(Other_Frame, Identification);
			} else if (protocol_type.equals("ICMP")) {
				System.out.println("3. ICMP");
				r += "3. ICMP<br>";
				icmp(Other_Frame);
			} else if (protocol_type.equals("UDP")) {
				System.out.println("3. UDP");
				r += "3. UDP<br>";
				udp(Other_Frame);
			} else {
				System.out.println("�������� ������ �м��� �� �����ϴ�.");
				r += "�������� ������ �м��� �� �����ϴ�.<br>";
			}
		}
	}

	// Service Type �м�
	public static void Service_Type(String Type) {
		System.out.print(" 3) Service Type : " + Type + " / ");
		r += " 3) Service Type : " + Type + " / ";

		// Service Type == 00 �� ��쿡 No Service Type
		if (Type.equals("00")) {
			System.out.println("No service type");
			r += "No service type<br>";
		}

		// Service Type != 00 �� ��쿡 Service Type ����
		else {
			System.out.print("service type  ");
			r += "service type  ";

			// Service Type�� 10������ ��ȯ
			int Type_10 = Integer.parseInt(Type, 16);

			// Service Type�� 2������ ��ȯ
			String Type_2 = Integer.toBinaryString(Type_10);

			// Service Type = DS + ECN �� �����ϱ� ���� �迭 ����
			String[] DS_ECN = new String[Type_2.length()];

			// DS + ECN �� �����ϱ� ���� �迭�� 2���� ������ ����
			for (int i = 0; i < DS_ECN.length; i++) {
				DS_ECN[i] = Character.toString(Type_2.charAt(i));
			}

			// DS�ʵ� �м�
			if (DS_ECN[Type_2.length() - 3].equals("0")) {
				System.out.print("DS : ǥ��  / ");
				r += "DS : ǥ��  / ";
			} else if ((DS_ECN[Type_2.length() - 4] + DS_ECN[Type_2.length() - 3]).equals("11")) {
				System.out.print("DS : �����/����  / ");
				r += "DS : �����/����  / ";
			} else if ((DS_ECN[Type_2.length() - 4] + DS_ECN[Type_2.length() - 3]).equals("01")) {
				System.out.print("DS : �����/����  / ");
				r += "DS : �����/����  / ";
			} else {
				System.out.print("DS / ");
				r += "DS / ";
			}

			// ECN�ʵ� �м�
			if ((DS_ECN[Type_2.length() - 2] + DS_ECN[Type_2.length() - 1]).equals("00")) {
				System.out.print("ECN : ��Ŷ�� ECN ����� ������� ���� ");
				r += "ECN : ��Ŷ�� ECN ����� ������� ���� ";
			} else if ((DS_ECN[Type_2.length() - 2] + DS_ECN[Type_2.length() - 1]).equals("01")) {
				System.out.print("ECN : �߽������� �������� ECN ����� �������� ��Ÿ�� ");
				r += "ECN : �߽������� �������� ECN ����� �������� ��Ÿ�� ";
			} else if ((DS_ECN[Type_2.length() - 2] + DS_ECN[Type_2.length() - 1]).equals("10")) {
				System.out.print("ECN : �߽������� �������� ECN ����� �������� ��Ÿ�� ");
				r += "ECN : �߽������� �������� ECN ����� �������� ��Ÿ�� ";
			} else if ((DS_ECN[Type_2.length() - 2] + DS_ECN[Type_2.length() - 1]).equals("11")) {
				System.out.print("ECN : ����Ͱ� ȥ���� �߻������� �˸������ϴ� ǥ�� ");
				r += "ECN : ����Ͱ� ȥ���� �߻������� �˸������ϴ� ǥ�� ";
			} else {
				System.out.print("ECN");
				r += "ECN";
			}
			System.out.println();
			r += "<br>";
		}
	}

	// Flags �м�
	public static void flags(String flag) {
		System.out.print(" 6) Flags : " + flag + " / ");
		r += " 6) Flags : " + flag + " / ";

		// Flags�� 10������ ��ȯ
		int flags_10 = Integer.parseInt(flag, 16);

		// Flags�� 2������ ��ȯ
		String flags_2 = Integer.toBinaryString(flags_10);

		// flags_2�� ���ڸ��� �߶� ����
		String[] flags_2_divide = new String[flags_2.length()];
		for (int i = 0; i < flags_2.length(); i++) {
			flags_2_divide[i] = Character.toString(flags_2.charAt(i));
		}

		// flags_2�� ũ�Ⱑ 1�϶� �缳��
		if (flags_2_divide.length == 1) {
			flags_2 = "00" + flags_2;
		}
		// flags_2�� ũ�Ⱑ 2�϶� �缳��
		else if (flags_2_divide.length == 2) {
			flags_2 = "0" + flags_2;
		}
		// flags_2�� ù��° ���� 1�̸� 0�� �߰� --> ���ڸ��� 0���� �����
		if (flags_2_divide[0].equals("1")) {
			flags_2 = "0" + flags_2;
		}

		// �����ǵ� Flags�� ���
		System.out.println(flags_2);
		r += flags_2 + "<br>";

		// R, D, M ��Ʈ ���ϱ�
		// �缳���� flags_2�� ���ڸ��� �߶� ����
		String[] flags_2_divide_new = new String[flags_2.length()];
		for (int i = 0; i < flags_2.length(); i++) {
			flags_2_divide_new[i] = Character.toString(flags_2.charAt(i));
		}

		// r��Ʈ ���ϱ�
		System.out.println("    - Reserve : " + flags_2_divide_new[0]);
		r += "    - Reserve : " + flags_2_divide_new[0] + "<br>";

		// d��Ʈ ���ϱ�
		System.out.print("    - Don't Fragment : " + flags_2_divide_new[1]);
		r += "    - Don't Fragment : " + flags_2_divide_new[1];
		if (flags_2_divide_new[1].equals("0")) {
			System.out.println(" / able to fragment");
			r += " / able to fragment<br>";
		} else if (flags_2_divide_new[1].equals("1")) {
			System.out.println(" / Unable to fragment");
			r += " / Unable to fragment<br>";
		} else {
			System.out.println();
			r += "<br>";
		}

		// m��Ʈ ���ϱ�
		System.out.print("    - More : " + flags_2_divide_new[2]);
		r += "    - More : " + flags_2_divide_new[2];
		if (flags_2_divide_new[2].equals("0")) {
			System.out.println(" / No more fragments");
			r += " / No more fragments<br>";
		} else if (flags_2_divide_new[2].equals("1")) {
			System.out.println(" / more fragment");
			r += " / more fragment<br>";
		} else {
			System.out.println();
			r += "<br>";
		}
	}

	// TTL �м�
	public static void ttl(String tTL) {
		System.out.print(" 8) TTL : " + tTL + " / ");
		r += " 8) TTL : " + tTL + " / ";

		// TTL 16������ 10������ ��ȯ
		int TTL_10 = Integer.parseInt(tTL, 16);
		System.out.println(TTL_10 + " hops");
		r += TTL_10 + " hops<br>";
	}

	// Protocol �м�
	public static void protocol(String protocol) {

		// Protocol 16���� -> 10������
		int p_10 = Integer.parseInt(protocol, 16);

		System.out.print(" 9) Protocol : " + p_10 + " / ");
		r += " 9) Protocol : " + p_10 + " / ";
		if (p_10 == 1) {
			System.out.println("ICMP");
			r += "ICMP<br>";
		} else if (p_10 == 2) {
			System.out.println("IGMP");
			r += "IGMP<br>";
		} else if (p_10 == 6) {
			System.out.println("TCP");
			r += "TCP<br>";
		} else if (p_10 == 8) {
			System.out.println("EGP");
			r += "EGP<br>";
		} else if (p_10 == 17) {
			System.out.println("UDP");
			r += "UDP<br>";
		} else if (p_10 == 89) {
			System.out.println("OSPF");
			r += "OSPF<br>";
		} else {
			System.out.println("Ȯ�� �Ұ�");
			r += "Ȯ�� �Ұ�<br>";
		}

	}

	// Protocol�� �м��Ͽ� �ٸ� Protocol ����
	public static String protocol_finding(String protocol) {

		String result = "";
		// Protocol 16���� -> 10������
		int p_10 = Integer.parseInt(protocol, 16);

		if (p_10 == 1) {
			result = "ICMP";
		} else if (p_10 == 2) {
			result = "IGMP";
		} else if (p_10 == 6) {
			result = "TCP";
		} else if (p_10 == 8) {
			result = "EGP";
		} else if (p_10 == 17) {
			result = "UDP";
		} else if (p_10 == 89) {
			result = "OSPF";
		} else {
			result = "�������� �м� �Ұ���";
		}
		return result;
	}

	// IP Address 16���� -> 10���� �� ���ϱ�
	public static void IP_16_10(String address) {

		// �߷��� �ּ� ���� �����
		String address_1 = address.substring(0, 2);
		String address_2 = address.substring(2, 4);
		String address_3 = address.substring(4, 6);
		String address_4 = address.substring(6, 8);

		// ����յ� 16������ 10������ ��ȯ
		int address_10_1 = Integer.parseInt(address_1, 16);
		int address_10_2 = Integer.parseInt(address_2, 16);
		int address_10_3 = Integer.parseInt(address_3, 16);
		int address_10_4 = Integer.parseInt(address_4, 16);

		// Source Address�� 10���� �� ���
		System.out.println(address_10_1 + "." + address_10_2 + "." + address_10_3 + "." + address_10_4);
		r += address_10_1 + "." + address_10_2 + "." + address_10_3 + "." + address_10_4 + "<br>";
	}

	// IP Option Number �м�
	public static String ip_option(String option) {
		String result = "";

		// IP Option Number�� 2������ 10������ ��ȯ
		String op = option.substring(0, 2);
		int o_2 = Integer.parseInt(op, 16);

		if (o_2 == 0) {
			result = "End of Options List";
		} else if (o_2 == 1) {
			result = "No Operation";
		} else if (o_2 == 130) {
			result = "Security";
		} else if (o_2 == 131) {
			result = "Loose Source Router";
		} else if (o_2 == 68) {
			result = "Time Stamp";
		} else if (o_2 == 133) {
			result = "Extended Security";
		} else if (o_2 == 134) {
			result = "Commercial Security";
		} else if (o_2 == 7) {
			result = "Record Route";
		} else if (o_2 == 136) {
			result = "Stream ID";
		} else if (o_2 == 137) {
			result = "Strict Source Router";
		} else if (o_2 == 10) {
			result = "Experimental Measurement";
		} else if (o_2 == 11) {
			result = "MTU Probe";
		} else if (o_2 == 12) {
			result = "MTU Reply";
		} else if (o_2 == 205) {
			result = "Experimental Flow Control";
		} else if (o_2 == 142) {
			result = "Experimental Access Control";
		} else if (o_2 == 15) {
			result = "???";
		} else if (o_2 == 144) {
			result = "IMI Traffic Descriptor";
		} else if (o_2 == 145) {
			result = "Traceroute";
		} else if (o_2 == 148) {
			result = "Router Alert";
		} else if (o_2 == 149) {
			result = "Selective Directed Broadcast";
		} else if (o_2 == 150) {
			result = "Unassigned (Released 18 October 2005)";
		} else if (o_2 == 151) {
			result = "Dynamic Packet State";
		} else if (o_2 == 152) {
			result = "Upstream Multicast Pkt";
		} else if (o_2 == 25) {
			result = "Quick-Start";
		} else if (o_2 == 30) {
			result = "RFC3692-style Experiment";
		} else if (o_2 == 94) {
			result = "RFC3692-style Experiment";
		} else if (o_2 == 158) {
			result = "RFC3692-style Experiment";
		} else if (o_2 == 222) {
			result = "RFC3692-style Experiment";
		} else {
			result = "Ȯ�� �Ұ�";
		}

		return result;

	}

	// ARP �м�
	public static void arp(String format) {

		// Format�� ����� 1�� ���
		if (format.length() < 56) {
			System.out.println("�ٽ� ���� �Է����ּ���!");
			r += "�ٽ� ���� �Է����ּ���!<br>";
		} else {

			// ARP Format �и��ϱ�
			String[] ArpFormat = new String[format.length()];
			for (int i = 0; i < format.length(); i++) {
				ArpFormat[i] = Character.toString(format.charAt(i));
			}

			// H/W type �м�
			String HW = format.substring(0, 4);
			System.out.print(" 1) H/W Type : " + HW + " / ");
			r += " 1) H/W Type : " + HW + " / ";
			int HW_10 = Integer.parseInt(HW, 16); // ����յ� 16������ 10������ ��ȯ
			HW_TYPE(HW_10); // ���ǿ� ���߾� H/W type �� �м�

			// Protocol type �м�
			String PT = format.substring(4, 8);
			System.out.println(" 2) Protocol Type : " + PT + " / " + Protocol(PT));
			r += " 2) Protocol Type : " + PT + " / " + Protocol(PT) + "<br>";

			// H/W Size �м�
			String HWS = format.substring(8, 10);
			System.out.print(" 3) H/W Size : " + HWS + " / ");
			r += " 3) H/W Size : " + HWS + " / ";

			// H/W_16�� 10������ ��ȯ
			int HWS_10 = Integer.parseInt(HWS, 16);
			System.out.println(HWS_10 * 8 + " bits");
			r += HWS_10 * 8 + " bits<br>";

			// Protocol Size �м�
			String protocol = format.substring(10, 12);
			System.out.print(" 4) Protocol Size : " + protocol + " / ");
			r += " 4) Protocol Size : " + protocol + " / ";

			// Protocol�� 10���� ��ȯ
			int protocol_10 = Integer.parseInt(protocol, 16);
			System.out.println(protocol_10 * 8 + " bits");
			r += protocol_10 * 8 + " bits<br>";

			// Operation �м�
			String Operation = format.substring(12, 16);
			System.out.print(" 5) Operation : " + Operation + " / ");
			r += " 5) Operation : " + Operation + " / ";
			operation(Operation);

			// Sender MAC Address �м�
			System.out.print(" 6) Sender MAC Address : ");
			r += " 6) Sender MAC Address : ";
			String SenderMacAddress = "";
			for (int i = 16; i < 28; i++) {
				if (i % 2 == 1 && i != 27) {
					System.out.print(ArpFormat[i]);
					System.out.print(":");
					r += ArpFormat[i] + ":";
				} else {
					System.out.print(ArpFormat[i]);
					r += ArpFormat[i];
				}
				SenderMacAddress = SenderMacAddress + ArpFormat[i];
			}

			// Sender Mac Address�� ���� �迭�� �и� ����
			String[] SMA = new String[SenderMacAddress.length()];
			for (int i = 0; i < SMA.length; i++) {
				SMA[i] = Character.toString(SenderMacAddress.charAt(i));
			}
			System.out.println(" / " + CheckData(SMA));
			r += " / " + CheckData(SMA) + "<br>";

			// Sender IP Address �м�
			String SenderIpAddress = format.substring(28, 36);
			System.out.print(" 7) Sender IP Address : " + SenderIpAddress + " / ");
			r += " 7) Sender IP Address : " + SenderIpAddress + " / ";
			IP_16_10(SenderIpAddress);

			// Target Mac Address �м�
			System.out.print(" 8) Target MAC Address : ");
			r += " 8) Target MAC Address : ";
			String TargetMacAddress = "";
			for (int i = 36; i < 48; i++) {
				if (i % 2 == 1 && i != 27) {
					System.out.print(ArpFormat[i]);
					System.out.print(":");
					r += ArpFormat[i] + ":";
				} else {
					System.out.print(ArpFormat[i]);
					r += ArpFormat[i];
				}
				TargetMacAddress = TargetMacAddress + ArpFormat[i];
			}

			// Target Mac Address�� ���� �迭�� �и� ����
			String[] TMA = new String[TargetMacAddress.length()];
			for (int i = 0; i < SMA.length; i++) {
				TMA[i] = Character.toString(TargetMacAddress.charAt(i));
			}
			System.out.println(" / " + CheckData(TMA));
			r += " / " + CheckData(TMA) + "<br>";

			// Target IP Address �м�
			String TargetIpAddress = format.substring(48, 56);
			System.out.print(" 9) Target IP Address : " + TargetIpAddress + " / ");
			r += " 9) Target IP Address : " + TargetIpAddress + " / ";
			IP_16_10(TargetIpAddress);
		}
	}

	// Hardware ���� ���� Type ��
	public static void HW_TYPE(int hw_10) {
		if (hw_10 == 0) {
			System.out.println("Reserved");
			r += "Reserved<br>";
		} else if (hw_10 == 1) {
			System.out.println("Ethernet");
			r += "Ethernet<br>";
		} else if (hw_10 == 2) {
			System.out.println("Experimental Ethernet");
			r += "Experimental Ethernet<br>";
		} else if (hw_10 == 3) {
			System.out.println("Amateur Radio AX.25");
			r += "Amateur Radio AX.25<br>";
		} else if (hw_10 == 4) {
			System.out.println("Proteon ProNET Token Ring");
			r += "Proteon ProNET Token Ring<br>";
		} else if (hw_10 == 5) {
			System.out.println("Chaos");
			r += "Chaos<br>";
		} else if (hw_10 == 6) {
			System.out.println("IEEE 802 Networks");
			r += "IEEE 802 Networks<br>";
		} else if (hw_10 == 7) {
			System.out.println("ARCNET");
			r += "ARCNET<br>";
		} else if (hw_10 == 7) {
			System.out.println("ARCNET");
			r += "ARCNET<br>";
		} else if (hw_10 == 8) {
			System.out.println("Hyperchannel");
			r += "Hyperchannel<br>";
		} else if (hw_10 == 9) {
			System.out.println("Lanstar");
			r += "Lanstar<br>";
		} else if (hw_10 == 10) {
			System.out.println("Autonet Short Address");
			r += "Autonet Short Address<br>";
		} else if (hw_10 == 11) {
			System.out.println("LocalTalk");
			r += "LocalTalk<br>";
		} else if (hw_10 == 12) {
			System.out.println("LocalNet");
			r += "LocalNet<br>";
		} else if (hw_10 == 13) {
			System.out.println("Ultra link");
			r += "Ultra link<br>";
		} else if (hw_10 == 14) {
			System.out.println("SMDS");
			r += "SMDS<br>";
		} else if (hw_10 == 15) {
			System.out.println("Frame Relay");
			r += "Frame Relay<br>";
		} else if (hw_10 == 16) {
			System.out.println("Asynchronous Transmission Mode");
			r += "Asynchronous Transmission Mode<br>";
		} else if (hw_10 == 17) {
			System.out.println("HDLC");
			r += "HDLC<br>";
		} else if (hw_10 == 18) {
			System.out.println("Fibre Channel");
			r += "Fibre Channel<br>";
		} else if (hw_10 == 19) {
			System.out.println("Asynchronous Transmission Mode");
			r += "Asynchronous Transmission Mode<br>";
		} else if (hw_10 == 20) {
			System.out.println("Serial Line");
			r += "Serial Line<br>";
		} else if (hw_10 == 21) {
			System.out.println("Asynchronous Transmission Mode");
			r += "Asynchronous Transmission Mode<br>";
		} else if (hw_10 == 22) {
			System.out.println("MIL-STD-188-220");
			r += "MIL-STD-188-220<br>";
		} else if (hw_10 == 23) {
			System.out.println("Metricom");
			r += "Metricom<br>";
		} else if (hw_10 == 24) {
			System.out.println("IEEE 1394.1995");
			r += "IEEE 1394.1995<br>";
		} else if (hw_10 == 25) {
			System.out.println("MAPOS");
			r += "MAPOS<br>";
		} else if (hw_10 == 26) {
			System.out.println("Twinaxial");
			r += "Twinaxial<br>";
		} else if (hw_10 == 27) {
			System.out.println("EUI-64l");
			r += "EUI-64l<br>";
		} else if (hw_10 == 28) {
			System.out.println("HIPARP");
			r += "HIPARP<br>";
		} else if (hw_10 == 29) {
			System.out.println("IP and ARP over ISO 7816-3");
			r += "IP and ARP over ISO 7816-3<br>";
		} else if (hw_10 == 30) {
			System.out.println("ARPSec");
			r += "ARPSec<br>";
		} else if (hw_10 == 31) {
			System.out.println("IPsec tunnel");
			r += "IPsec tunnel<br>";
		} else if (hw_10 == 32) {
			System.out.println("InfiniBand (TM)");
			r += "InfiniBand (TM)<br>";
		} else if (hw_10 == 33) {
			System.out.println("TIA-102 Project 25 Common Air Interface (CAI)");
			r += "TIA-102 Project 25 Common Air Interface (CAI)<br>";
		} else if (hw_10 == 34) {
			System.out.println("Wiegand Interface");
			r += "Wiegand Interface<br>";
		} else if (hw_10 == 35) {
			System.out.println("Pure IP");
			r += "Pure IP<br>";
		} else if (hw_10 == 36) {
			System.out.println("HW_EXP1");
			r += "HW_EXP1<br>";
		} else if (hw_10 == 37) {
			System.out.println("HFI");
			r += "HFI<br>";
		} else if (hw_10 >= 38 && hw_10 <= 255) {
			System.out.println("Unassigned");
			r += "Unassigned<br>";
		} else if (hw_10 == 256) {
			System.out.println("HW_EXP2");
			r += "HW_EXP2<br>";
		} else if (hw_10 == 257) {
			System.out.println("AEthernet");
			r += "AEthernet<br>";
		} else if (hw_10 >= 258 && hw_10 <= 65534) {
			System.out.println("Unassigned");
			r += "Unassigned<br>";
		} else if (hw_10 == 65535) {
			System.out.println("Reserved");
			r += "Reserved<br>";
		} else {
			System.out.println("Ȯ�� �Ұ�");
			r += "Ȯ�� �Ұ�<br>";
		}

	}

	// Protocol ���� ã��
	public static String Protocol(String protocol) {
		String result = "";
		if (protocol.equals("0800")) {
			result = "IP";
		} else if (protocol.equals("0806")) {
			result = "ARP";
		} else if (protocol.equals("0600")) {
			result = "XNS IDP";
		} else if (protocol.equals("0805")) {
			result = "X.25 PLP";
		} else if (protocol.equals("0835")) {
			result = "RARP";
		} else if (protocol.equals("8137")) {
			result = "NetwareIPX";
		} else if (protocol.equals("8191")) {
			result = "NetBIOS";
		} else if (protocol.equals("8100")) {
			result = "VLAN ID";
		} else if (protocol.equals("86dd")) {
			result = "IPv6";
		} else if (protocol.equals("8847")) {
			result = "MPLS";
		} else if (protocol.equals("8863")) {
			result = "PPPoE Discovery Stage";
		} else if (protocol.equals("8864")) {
			result = "PPPoE PPP Session Stage";
		} else if (protocol.equals("888e")) {
			result = "IEEE 802.1X";
		} else {
			result = "�м� �Ұ���";
		}
		return result;
	}

	// Operation ���� �м�
	public static void operation(String op) {
		int operation_10 = Integer.parseInt(op, 16);

		if (operation_10 == 1) {
			System.out.println("ARP Request");
			r += "ARP Request<br>";
		} else if (operation_10 == 2) {
			System.out.println("ARP Reply");
			r += "ARP Reply<br>";
		} else if (operation_10 == 3) {
			System.out.println("RARP Request");
			r += "RARP Request<br>";
		} else if (operation_10 == 4) {
			System.out.println("RARP Reply");
			r += "RARP Reply<br>";
		} else {
			System.out.println("�м� �Ұ���");
			r += "�м� �Ұ���<br>";
		}
	}

	// TCP FRAME �м� -- �Ű������� Identification�� TCP FRAME�� Flag���� �м��ϱ� ����!
	public static void tcp(String tcp_frame, String Identification) {

		// Format�� ����� 1�� ���
		if (tcp_frame.length() < 20 * 2) {
			System.out.println("�ٽ� ���� �Է����ּ���!");
			r += "�ٽ� ���� �Է����ּ���!<br>";
		} else {
			// SourcePort �м�
			String SourcePort = tcp_frame.substring(0, 4);
			System.out.print(" 1) Source Port : " + SourcePort + " / ");
			r += " 1) Source Port : " + SourcePort + " / ";
			int SP_10 = Integer.parseInt(SourcePort, 16);
			System.out.print(SP_10);
			r += SP_10;

			// ��Ʈ��ȣ�� ������ ���� �м�
			if (SP_10 >= 0 && SP_10 <= 1023) {
				System.out.print("(Well-Known Port) : ");
				r += "(Well-Known Port) : ";
				System.out.println(Port("TCP", SP_10));
				r += Port("TCP", SP_10) + "<br>";
			} else if (SP_10 >= 1024 && SP_10 <= 49151) {
				System.out.println("(Registered Port) : Organization or buisness Port");
				r += "(Registered Port) : Organization or buisness Port<br>";
			} else if (SP_10 >= 49152 && SP_10 <= 65535) {
				System.out.println("(Dynamic Port) : Client Port");
				r += "(Dynamic Port) : Client Port<br>";
			} else {
				System.out.println("�м� �Ұ���");
				r += "�м� �Ұ���<br>";
			}

			// Destination Port �м�
			String DestinationPort = tcp_frame.substring(4, 8);
			System.out.print(" 2) Destination Port : " + DestinationPort + " / ");
			r += " 2) Destination Port : " + DestinationPort + " / ";
			int DP_10 = Integer.parseInt(DestinationPort, 16);
			System.out.print(DP_10);

			// ��Ʈ��ȣ�� ������ ���� �м�
			if (DP_10 >= 0 && DP_10 <= 1023) {
				System.out.print("(Well-Known Port) : ");
				r += "(Well-Known Port) : ";
				System.out.println(Port("TCP", DP_10));
				r += Port("TCP", DP_10) + "<br>";
			} else if (DP_10 >= 1024 && DP_10 <= 49151) {
				System.out.println("(Registered Port) : Organization or buisness Port");
				r += "(Registered Port) : Organization or buisness Port<br>";
			} else if (DP_10 >= 49152 && DP_10 <= 65535) {
				System.out.println("(Dynamic Port) : Client Port");
				r += "(Dynamic Port) : Client Port<br>";
			} else {
				System.out.println("�м� �Ұ���");
				r += "�м� �Ұ���<br>";
			}

			// Sequence number �м�
			String SequenceNumber = tcp_frame.substring(8, 16);
			System.out.println(" 3) Sequence number : " + SequenceNumber);
			r += " 3) Sequence number : " + SequenceNumber + "<br>";

			// ACK number �м�
			String AckNumber = tcp_frame.substring(16, 24);
			System.out.println(" 4) Ack number : " + AckNumber);
			r += " 4) Ack number : " + AckNumber + "<br>";

			// Header Length �м�
			String HeaderLength = tcp_frame.substring(24, 25);
			System.out.print(" 5) Header Length : " + HeaderLength + " / ");
			r += " 5) Header Length : " + HeaderLength + " / ";

			int HL_10 = Integer.parseInt(HeaderLength, 16);
			// �ɼ��� ���� ���
			if (HL_10 * 4 == 20) {
				System.out.println(HL_10 * 4 + " bytes : No option");
				r += HL_10 * 4 + " bytes : No option<br>";
			}
			// �ɼ��� ���� ���
			else if (HL_10 * 4 > 20 && HL_10 * 4 <= 60) {
				System.out.println(HL_10 * 4 + " bytes : option " + (HL_10 * 4 - 20) + " bytes");
				r += HL_10 * 4 + " bytes : option " + (HL_10 * 4 - 20) + " bytes<br>";
			}
			// ����ó��
			else {
				System.out.println("������ �������� ���մϴ�.");
				r += "������ �������� ���մϴ�.<br>";
			}

			// Control Bits �м�
			String ControlBit = tcp_frame.substring(26, 28);
			// 10������ ��ȯ
			int CB_10 = Integer.parseInt(ControlBit, 16);
			// 16���� Control Bits ���
			System.out.print(" 6) Control Bits : " + ControlBit + " / ");
			r += " 6) Control Bits : " + ControlBit + " / ";

			// 16������ 2������ ��ȯ
			String CB_2 = Integer.toBinaryString(CB_10);
			String CB_2_new = "";
			if (CB_2.length() == 1) {
				CB_2_new = "0000000" + CB_2;
				System.out.println(CB_2_new);
				r += CB_2_new + "<br>";
			} else if (CB_2.length() == 2) {
				CB_2_new = "000000" + CB_2;
				System.out.println(CB_2_new);
				r += CB_2_new + "<br>";
			} else if (CB_2.length() == 3) {
				CB_2_new = "00000" + CB_2;
				System.out.println(CB_2_new);
				r += CB_2_new + "<br>";
			} else if (CB_2.length() == 4) {
				CB_2_new = "0000" + CB_2;
				System.out.println(CB_2_new);
				r += CB_2_new + "<br>";
			} else if (CB_2.length() == 5) {
				CB_2_new = "000" + CB_2;
				System.out.println(CB_2_new);
				r += CB_2_new + "<br>";
			} else if (CB_2.length() == 6) {
				CB_2_new = "00" + CB_2;
				System.out.println(CB_2_new);
				r += CB_2_new + "<br>";
			} else if (CB_2.length() == 7) {
				CB_2_new = "0" + CB_2;
				System.out.println(CB_2_new);
				r += CB_2_new + "<br>";
			} else if (CB_2.length() == 8) {
				CB_2_new = CB_2;
				System.out.println(CB_2_new);
				r += CB_2_new + "<br>";
			} else if (CB_2.length() == 0) {
				CB_2_new = "00000000";
				System.out.println(CB_2_new);
				r += CB_2_new + "<br>";
			} else {
				CB_2_new = CB_2;
				System.out.println(CB_2_new);
				r += CB_2_new + "<br>";
			}

			// Control bit�� 2���� ���� �迭�� ����
			String[] Cb = new String[CB_2_new.length()];
			for (int i = 0; i < CB_2_new.length(); i++) {
				Cb[i] = Character.toString(CB_2_new.charAt(i));
			}
			String Urgent = Cb[Cb.length - 6];
			String Ack = Cb[Cb.length - 5];
			String Push = Cb[Cb.length - 4];
			String Reset = Cb[Cb.length - 3];
			String Syn = Cb[Cb.length - 2];
			String Fin = Cb[Cb.length - 1];

			// Urgent �м�
			if (Urgent.equals("0")) {
				System.out.println("  - Urgent : 0 / Not urgent");
				r += "  - Urgent : 0 / Not urgent<br>";
			} else {
				System.out.println("  - Urgent : 1 / urgent");
				r += "  - Urgent : 1 / urgent<br>";
			}

			// Ack �м�
			if (Ack.equals("0")) {
				System.out.println("  - Ack : 0 / Not Include Acknowlegment");
				r += "  - Ack : 0 / Not Include Acknowlegment<br>";
			} else {
				System.out.println("  - Ack : 1 / Acknowlegment");
				r += "  - Ack : 1 / Acknowlegment<br>";
			}

			// Push �м�
			if (Push.equals("0")) {
				System.out.println("  - Push : 0 / Normal");
				r += "  - Push : 0 / Normal<br>";
			} else {
				System.out.println("  - Push : 1 / Fast");
				r += "  - Push : 1 / Fast<br>";
			}

			// Reset �м�
			if (Reset.equals("0")) {
				System.out.println("  - Reset : 0 / Normal");
				r += "  - Reset : 0 / Normal<br>";
			} else {
				System.out.println("  - Reset : 1 / Reset");
				r += "  - Reset : 1 / Reset<br>";
			}

			// Syn �м�
			if (Syn.equals("1") && Ack.equals("0") && !Identification.equals("0000")) {
				System.out.println("  - Syn : 1 / Connection Request");
				r += "  - Syn : 1 / Connection Request<br>";
			} else if (Syn.equals("1") && Ack.equals("1") && Identification.equals("0000")) {
				System.out.println("  - Syn : 1 / Connection Permission");
				r += "  - Syn : 1 / Connection Permission<br>";
			} else if (Ack.equals("1") && !Identification.equals("0000")) {
				System.out.println("  - Syn : 1 / Connection Setup");
				r += "  - Syn : 1 / Connection Setup<br>";
			} else if (Syn.equals("1")) {
				System.out.println("  - Syn : 1 / Connection Not Setup");
				r += "  - Syn : 1 / Connection Not Setup<br>";
			} else if (Syn.equals("0")) {
				System.out.println("  - Syn : 0 / Connection Not Setup");
				r += "  - Syn : 0 / Connection Not Setup<br>";
			}

			// Fin �м�
			if (Fin.equals("0")) {
				System.out.println("  - Fin : 0 / Not Connection Release");
				r += "  - Fin : 0 / Not Connection Release<br>";
			} else if (Fin.equals("1") && Ack.equals("1")) {
				System.out.println("  - Fin : 1 / Finish Response");
				r += "  - Fin : 1 / Finish Response<br>";
			} else if (Fin.equals("1") && (Ack.equals("0") != true)) {
				System.out.println("  - Fin : 1 / Finish Request");
				r += "  - Fin : 1 / Finish Request<br>";
			} else if (Fin.equals("1")) {
				System.out.println("  - FIN : 1");
				r += "  - FIN : 1<br>";
			}

			// Windows �м�
			String Windows = tcp_frame.substring(28, 32);
			System.out.print(" 7) Window Size : " + Windows + " / ");
			r += " 7) Window Size : " + Windows + " / ";
			// 16���� -> 10����
			int W_10 = Integer.parseInt(Windows, 16);
			System.out.println(W_10 + " bytes");
			r += W_10 + " bytes<br>";

			// Checksum �м�
			String Checksum = tcp_frame.substring(32, 36);
			System.out.println(" 8) Checksum : " + Checksum);
			r += " 8) Checksum : " + Checksum + "<br>";

			// Urgent Point �м�
			String UrgentPoint = tcp_frame.substring(36, 40);
			if (UrgentPoint.equals("0000")) {
				System.out.println(" 9) Urgent Point : " + UrgentPoint + " / Not Urgent");
				r += " 9) Urgent Point : " + UrgentPoint + " / Not Urgent<br>";
			} else {
				System.out.println(" 9) Urgent Point : " + UrgentPoint + " / Urgent");
				r += " 9) Urgent Point : " + UrgentPoint + " / Urgent<br>";
			}

			// tcp ����� ���̰� 20�� ���� ��� option�� ������!
			if (!(HL_10 * 4 == 20)) {
				// Option �м�
				String Option = tcp_frame.substring(40, tcp_frame.length());
				System.out.println(" 10) Option Data : " + Option + " / " + 4 * Option.length() / 8 + " bytes");
				r += " 10) Option Data : " + Option + " / " + 4 * Option.length() / 8 + " bytes<br>";

				// option�� kind
				if (HL_10 * 4 >= 21) {
					String option_kind = tcp_frame.substring(40, 42);
					System.out.print("  - kind : " + option_kind + " / ");
					r += "  - kind : " + option_kind + " / ";

					// �ɼ� ���� �м�
					int OK_10 = Integer.parseInt(option_kind, 16);
					if (OK_10 == 0) {
						System.out.println("End of Option");
						r += "End of Option<br>";
					} else if (OK_10 == 1) {
						System.out.println("No Operation");
						r += "No Operation<br>";
					} else if (OK_10 == 2) {
						System.out.println("Maximum Segment Size (MSS)");
						r += "Maximum Segment Size (MSS)<br>";
					} else if (OK_10 == 3) {
						System.out.println("Window Scale factor");
						r += "Window Scale factor<br>";
					} else if (OK_10 == 4) {
						System.out.println("Selective Acknowledgment Permitted (Selective Reject)");
						r += "Selective Acknowledgment Permitted (Selective Reject)<br>";
					} else if (OK_10 == 5) {
						System.out.println("Selective Acknowledgment Data");
						r += "Selective Acknowledgment Data<br>";
					} else if (OK_10 == 8) {
						System.out.println("Timestamp");
						r += "Timestamp<br>";
					} else {
						System.out.println();
						r += "<br>";
					}
				}

				// option�� length
				if (HL_10 * 4 >= 22) {
					String option_length = tcp_frame.substring(42, 44);
					System.out.print("  - length : " + option_length + " / ");
					r += "  - length : " + option_length + " / ";

					int OL = Integer.parseInt(option_length, 16);
					System.out.println(OL + "byte");
					r += OL + "byte<br>";
				}

				// option�� value
				if (HL_10 * 4 > 22) {
					String option_value = tcp_frame.substring(44, tcp_frame.length());
					System.out.println("  - value : " + option_value);
				}
			}
		}
	}

	// TCP / UDP��Ʈ Ȯ���ϱ�
	public static String Port(String what, int port) {
		String T = "";
		String U = "";
		String R = "";

		// ��ȣ�� ���� TCP / UDP Port ��Ī
		if (port == 0) {
			U = "Reserved";
		} else if (port == 1) {
			T = "TCPMUX";
		} else if (port == 7) {
			T = "ECHO";
			U = "ECHO";
		} else if (port == 9) {
			T = "Discard";
			U = "DIscard";
		} else if (port == 13) {
			T = "Daytime";
			U = "Daytime";
		} else if (port == 17) {
			T = "QOTD";
		} else if (port == 19) {
			T = "Chargen";
			U = "Chargen";
		} else if (port == 20) {
			T = "FTP";
		} else if (port == 21) {
			T = "FTP";
		} else if (port == 22) {
			T = "SSH";
		} else if (port == 23) {
			T = "Tellnet";
		} else if (port == 24) {
			T = "individual mail";
		} else if (port == 25) {
			T = "SMTP";
		} else if (port == 37) {
			T = "Time";
			U = "Time";
		} else if (port == 49) {
			U = "Tacacs";
		} else if (port == 53) {
			T = "DNS";
			U = "UDP";
		} else if (port == 67) {
			U = "Bootp";
		} else if (port == 68) {
			U = "Bootp";
		} else if (port == 69) {
			U = "TFTP";
		} else if (port == 70) {
			T = "gofer";
		} else if (port == 79) {
			T = "Finger";
		} else if (port == 80) {
			T = "HTTP / WWW";
			U = "HTTP / WWW";
		} else if (port == 88) {
			T = "Ŀ���ν�";
		} else if (port == 109) {
			T = "Pop2";
		} else if (port == 110) {
			T = "pop3";
		} else if (port == 113) {
			T = "ident";
		} else if (port == 119) {
			T = "NTTP";
		} else if (port == 123) {
			U = "NTP";
		} else if (port == 139) {
			T = "Netbios";
		} else if (port == 143) {
			T = "IMAP4";
		} else if (port == 161) {
			U = "SNMP";
		} else if (port == 162) {
			U = "SNMP";
		} else if (port == 179) {
			T = "BGP";
		} else if (port == 194) {
			T = "IRC";
		} else if (port == 389) {
			T = "LDAP";
		} else if (port == 443) {
			T = "HTTPS";
		} else if (port == 445) {
			U = "Microsoft-DS";
			T = "Microsoft-DS";
		} else if (port == 514) {
			U = "Syslog";
		} else if (port == 515) {
			T = "LPD";
		} else if (port == 540) {
			T = "UUCP";
		} else if (port == 542) {
			T = "Commerce Applications";
			U = "Commerce Applications";
		} else if (port == 587) {
			T = "email message submission";
		} else if (port == 591) {
			T = "File maker";
		} else if (port == 636) {
			T = "LDAP";
		} else if (port == 666) {
			T = "Multiplayer Game";
		} else if (port == 873) {
			T = "rsync";
		} else if (port == 981) {
			T = "SofaWare Technologies Checkpoint Firewall-1";
		} else if (port == 990) {
			T = "SSL ���� FTP";
		} else if (port == 993) {
			T = "SSL ���� IMAP4";
		} else if (port == 995) {
			T = "SSL ���� POP3";
		} else if (port == 42) {
			T = "WINS ���� Windows ���ͳ� �̸� ����";
			U = "WINS ���� Windows ���ͳ� �̸� ����";
		} else if (port == 102) {
			T = "X.400 Microsoft Exchange MTA ����";
		} else if (port == 135) {
			T = "RPC";
		} else if (port == 137) {
			U = "UDP";
		} else if (port == 138) {
			U = "NetBIOS �����ͱ׷� ����";
		} else if (port == 464) {
			T = "Kerberos Password V5 Net Logon";
		} else if (port == 500) {
			U = "IPsec ISAKMP";
		} else if (port == 548) {
			T = "Macintosh";
		} else if (port == 554) {
			T = "RTSP Windows Media Service";
		} else if (port == 563) {
			T = "SSL ���� NNTP Network News Transfer Protocol";
		} else if (port == 593) {
			T = "RPC over HTTPS Exchange Server";
		} else {
			T = "";
		}

		// TCP / UDP ����
		if (what.equals("TCP")) {
			R = T;
		} else if (what.equals("UDP")) {
			R = U;
		} else {
			R = "";
		}

		return R;
	}

	// icmp �м�
	public static void icmp(String format) {

		// Format�� ����� �⺻��� ������ 8���� ���� ��� ����ó��!
		if (format.length() < 8) {
			System.out.println("�ٽ� ���� �Է����ּ���!");
			r += "�ٽ� ���� �Է����ּ���!<br>";
		} else {
			// Type �м�
			String Type = format.substring(0, 2);
			System.out.print(" 1) Type : " + Type + " / ");
			r += " 1) Type : " + Type + " / ";
			// 16������ 10������ ��ȯ
			int T_10 = Integer.parseInt(Type, 16);
			// type ��м�
			icmp_type(T_10);

			// Code �м�
			String Code = format.substring(2, 4);
			System.out.print(" 2) Code : " + Code);
			r += " 2) Code : " + Code;
			// 16������ 10������ ��ȯ
			int S_10 = Integer.parseInt(Code, 16);
			// code ��м�
			icmp_code(T_10, S_10);

			// Checksum �м�
			String Checksum = format.substring(4, 8);
			System.out.println(" 3) Checksum : " + Checksum);
			r += " 3) Checksum : " + Checksum + "<br>";

			// icmp �������� Ȯ��
			if (format.length() > 8) {

				// Identifier �м�
				if (format.length() > 8) {
					String Identifier = format.substring(8, 12);
					System.out.print(" 4) Identifier : " + Identifier + " / ");
					r += " 4) Identifier : " + Identifier + " / ";

					// 16������ 10������ ��ȯ
					int I_10 = Integer.parseInt(Identifier, 16);
					System.out.println(I_10);
					r += I_10 + "<br>";
				}

				// Sequence number �м�
				if (format.length() > 12) {
					String SN = format.substring(12, 16);
					System.out.print(" 5) Sequence Number : " + SN + " / ");
					r += " 5) Sequence Number : " + SN + " / ";

					// 16������ 10������ ��ȯ
					int SN_10 = Integer.parseInt(SN, 16);
					System.out.println(SN_10);
					r += SN_10 + "<br>";
				}

				// �⺻��� ������ ���м�
				if (format.length() > 16) {
					// �⺻�ش� ������ ������
					String Data = format.substring(16, format.length());

					// �񱳰� �����
					String ex = "";
					for (int i = 0; i < format.length() - 16; i++) {
						ex = ex + "0";
					}

					// ������ �߻��� ip�м�
					if (Data.equals(ex)) {
						System.out.println(" 6) Data : " + Data.length() / 2 + "byte / " + Data);
						r += " 6) Data : " + Data.length() / 2 + "byte / " + Data + "<br>";
					} else {
						// ������ �� ip�ּ�
						String EA = format.substring(16, format.length() - 16);
						System.out.println(" 6) Error Ip Header : " + EA);
						r += " 6) Error Ip Header : " + EA + "<br>";
						// �����Ͱ�
						String ED = format.substring(format.length() - 16, format.length());
						System.out.println(" 7) Error Ip Data : " + ED);
						r += " 7) Error Ip Data : " + ED + "<br>";
					}
				}
			} else {
				System.out.println("NO Identifier, NO Sequence Number, NO Data Section");
				r += "NO Identifier, NO Sequence Number, NO Data Section<br>";
			}
		}
	}

	// type �м�
	public static void icmp_type(int t) {
		if (t == 0) {
			System.out.println("Echo Reply");
			r += "Echo Reply<br>";
		} else if (t == 1) {
			System.out.println("Unassigned");
			r += "Unassigned<br>";
		} else if (t == 2) {
			System.out.println("Unassigned");
			r += "Unassigned<br>";
		} else if (t == 3) {
			System.out.println("Destination Unreachable");
			r += "Destination Unreachable<br>";
		} else if (t == 4) {
			System.out.println("Source Quench");
			r += "Source Quench<br>";
		} else if (t == 5) {
			System.out.println("Redirect");
			r += "Redirect<br>";
		} else if (t == 6) {
			System.out.println("Alternate Host Address");
			r += "Alternate Host Address<br>";
		} else if (t == 7) {
			System.out.println("Unassigned");
			r += "Unassigned<br>";
		} else if (t == 8) {
			System.out.println("Echo Request");
			r += "Echo Request<br>";
		} else if (t == 9) {
			System.out.println("Router Advertisement");
			r += "Router Advertisement<br>";
		} else if (t == 10) {
			System.out.println("Router Solicitation");
			r += "Router Solicitation<br>";
		} else if (t == 11) {
			System.out.println("Time Exceeded");
			r += "Time Exceeded<br>";
		} else if (t == 12) {
			System.out.println("Parameter Problem");
			r += "Parameter Problem<br>";
		} else if (t == 13) {
			System.out.println("Timestamp Request");
			r += "Timestamp Request<br>";
		} else if (t == 14) {
			System.out.println("Timestamp Reply");
			r += "Timestamp Reply<br>";
		} else if (t == 15) {
			System.out.println("Information Request");
			r += "Information Request<br>";
		} else if (t == 16) {
			System.out.println("Information Reply");
			r += "Information Reply<br>";
		} else if (t == 17) {
			System.out.println("Address Mask Request");
			r += "Address Mask Request<br>";
		} else if (t == 18) {
			System.out.println("Address Mask Request");
			r += "Address Mask Request<br>";
		} else if (t == 19) {
			System.out.println("Reserved (for Security)");
			r += "Reserved (for Security)<br>";
		} else if (t >= 20 && t <= 29) {
			System.out.println("Reserved (for Robustness Experiment)");
			r += "Reserved (for Robustness Experiment)<br>";
		} else if (t == 30) {
			System.out.println("Traceroute");
			r += "Traceroute<br>";
		} else if (t == 31) {
			System.out.println("Datagram Conversion Error");
			r += "Datagram Conversion Error<br>";
		} else if (t == 32) {
			System.out.println("Mobile Host Redirect");
			r += "Mobile Host Redirect<br>";
		} else if (t == 33) {
			System.out.println("IPv6 Where-Are-You");
			r += "IPv6 Where-Are-You<br>";
		} else if (t == 34) {
			System.out.println("IPv6 I-Am-Here");
			r += "IPv6 I-Am-Here<br>";
		} else if (t == 35) {
			System.out.println("Mobile Registration Request");
			r += "Mobile Registration Request<br>";
		} else if (t == 36) {
			System.out.println("Mobile Registration Reply");
			r += "Mobile Registration Reply<br>";
		} else if (t >= 37 && t <= 255) {
			System.out.println("Reserved");
			r += "Reserved<br>";
		} else {
			System.out.println();
			r += "<br>";
		}
	}

	// Icmp_code �м�
	public static void icmp_code(int t, int c) {
		if (t == 0) {
			if (c == 0) {
				System.out.println(" / No Code");
				r += " / No Code<br>";
			}
		} else if (t == 3) {
			if (c == 0) {
				System.out.println(" / Network Unreachable");
				r += " / Network Unreachable<br>";
			} else if (c == 1) {
				System.out.println(" / Host Unreachable");
				r += " / Host Unreachable<br>";
			} else if (c == 2) {
				System.out.println(" / Protocol Unreachable");
				r += " / Protocol Unreachable<br>";
			} else if (c == 3) {
				System.out.println(" / Port Unreachable");
				r += " / Port Unreachable<br>";
			} else if (c == 4) {
				System.out.println(" / Fragmentation Needed and Don't Fragment was Set");
				r += " / Fragmentation Needed and Don't Fragment was Set<br>";
			} else if (c == 5) {
				System.out.println(" / Source Route Failed");
				r += " / Source Route Failed<br>";
			} else if (c == 6) {
				System.out.println(" / Destination Network Unknown");
				r += " / Destination Network Unknown<br>";
			} else if (c == 7) {
				System.out.println(" / Destination Host Unknown");
				r += " / Destination Host Unknown<br>";
			} else if (c == 8) {
				System.out.println(" / Source Host Isolated");
				r += " / Source Host Isolated<br>";
			} else if (c == 9) {
				System.out.println(" / Communication with Destination Network is Administratively Prohibited");
				r += " / Communication with Destination Network is Administratively Prohibited<br>";
			} else if (c == 10) {
				System.out.println(" / Communication with Destination Host is Administratively Prohibited");
				r += " / Communication with Destination Host is Administratively Prohibited<br>";
			} else if (c == 11) {
				System.out.println(" / Destination Network Unreachable for Type of Service");
				r += " / Destination Network Unreachable for Type of Service<br>";
			} else if (c == 12) {
				System.out.println(" / Destination Host Unreachable for Type of Service");
				r += " / Destination Host Unreachable for Type of Service<br>";
			} else if (c == 13) {
				System.out.println(" / Communication Administratively Prohibited");
				r += " / Communication Administratively Prohibited<br>";
			} else if (c == 14) {
				System.out.println(" / Host Precedence Violation");
				r += " / Host Precedence Violation<br>";
			} else if (c == 15) {
				System.out.println(" / Precedence cutoff in effect");
				r += " / Precedence cutoff in effect<br>";
			}
		} else if (t == 4) {
			if (c == 0) {
				System.out.println(" / No Code");
				r += " / No Code<br>";
			}
		} else if (t == 5) {
			if (c == 0) {
				System.out.println(" / Redirect Datagram for the Network (or subnet)");
				r += " / Redirect Datagram for the Network (or subnet)<br>";
			} else if (c == 1) {
				System.out.println(" / Redirect Datagram for the Host");
				r += " / Redirect Datagram for the Host<br>";
			} else if (c == 2) {
				System.out.println(" / Redirect Datagram for the Type of Service and Network");
				r += " / Redirect Datagram for the Type of Service and Network<br>";
			} else if (c == 3) {
				System.out.println(" / Redirect Datagram for the Type of Service and Host");
				r += " / Redirect Datagram for the Type of Service and Host<br>";
			}
		} else if (t == 6) {
			if (c == 0) {
				System.out.println(" / Alternate Address for Host");
				r += " / Alternate Address for Host<br>";
			}
		} else if (t == 8) {
			if (c == 0) {
				System.out.println(" / No Code");
				r += " / No Code<br>";
			}
		} else if (t == 9) {
			if (c == 0) {
				System.out.println(" / Normal router advertisement");
				r += " / Normal router advertisement<br>";
			} else if (c == 16) {
				System.out.println(" / Does not route common traffic");
				r += " / Does not route common traffic<br>";
			}
		} else if (t == 10) {
			if (c == 0) {
				System.out.println(" / No Code");
				r += " / No Code<br>";
			}
		} else if (t == 11) {
			if (c == 0) {
				System.out.println(" / Time to Live exceeded in Transit");
				r += " / Time to Live exceeded in Transit<br>";
			} else if (c == 1) {
				System.out.println(" / Fragment Reassembly Time Exceeded");
				r += " / Fragment Reassembly Time Exceeded<br>";
			}

		} else if (t == 12) {
			if (c == 0) {
				System.out.println(" / Pointer indicates the error");
				r += " / Time to Live exceeded in Transit<br>";
			} else if (c == 1) {
				System.out.println(" / Missing a Required Option");
				r += " / Missing a Required Option<br>";
			} else if (c == 2) {
				System.out.println(" / Bad Length");
				r += " / Bad Length<br>";
			}
		} else if (t == 13) {
			if (c == 0) {
				System.out.println(" / No Code");
				r += " / No Code<br>";
			}
		} else if (t == 14) {
			if (c == 0) {
				System.out.println(" / No Code");
				r += " / No Code<br>";
			}
		} else if (t == 15) {
			if (c == 0) {
				System.out.println(" / No Code");
				r += " / No Code<br>";
			}
		} else if (t == 16) {
			if (c == 0) {
				System.out.println(" / No Code");
				r += " / No Code<br>";
			}
		} else if (t == 17) {
			if (c == 0) {
				System.out.println(" / No Code");
				r += " / No Code<br>";
			}
		} else if (t == 18) {
			if (c == 0) {
				System.out.println(" / No Code");
				r += " / No Code<br>";
			}
		} else if (t == 40) {
			if (c == 0) {
				System.out.println(" / Bad SPI");
				r += " / Bad SPI<br>";
			} else if (c == 1) {
				System.out.println(" / Authentication Failed");
				r += " / Authentication Failed<br>";
			} else if (c == 2) {
				System.out.println(" / Decompression Failed");
				r += " / Decompression Failed<br>";
			} else if (c == 3) {
				System.out.println(" / Decryption Failed");
				r += " / Decryption Failed<br>";
			} else if (c == 4) {
				System.out.println(" / Need Authentication");
				r += " / Need Authentication<br>";
			} else if (c == 5) {
				System.out.println(" / Need Authorization");
				r += " / Need Authorization<br>";
			}
		}

		else {
			System.out.println();
			r += "<br>";
		}

	}

	// UDP �м�
	public static void udp(String format) {

		// Format�� ����� 1�� ���
		if (format.length() < 16) {
			System.out.println("�ٽ� ���� �Է����ּ���!");
			r += "�ٽ� ���� �Է����ּ���!<br>";
		}
		// Format�� ���°� �����϶�
		else {
			// Source port number �м�
			String SPN = format.substring(0, 4);
			System.out.print(" 1) Source Port Number : " + SPN + " / ");
			r += " 1) Source Port Number : " + SPN + " / ";

			// 16������ 10������
			int SPN_10 = Integer.parseInt(SPN, 16);
			// ��Ʈ��ȣ�� ������ ���� �м�
			if (SPN_10 >= 0 && SPN_10 <= 1023) {
				System.out.print("(Well-Known Port) : ");
				r += "(Well-Known Port) : ";
				System.out.println(Port("UDP", SPN_10));
				r += Port("UDP", SPN_10) + "<br>";
			} else if (SPN_10 >= 1024 && SPN_10 <= 49151) {
				System.out.println("(Registered Port) : Organization or buisness Port");
				r += "(Registered Port) : Organization or buisness Port<br>";
			} else if (SPN_10 >= 49152 && SPN_10 <= 65535) {
				System.out.println("(Dynamic Port) : Client Port");
				r += "(Dynamic Port) : Client Port<br>";
			} else {
				System.out.println();
				r += "<br>";
			}

			// Destination port number �м�
			String DPN = format.substring(4, 8);
			System.out.print(" 2) Destination Port Number : " + DPN + " / ");
			r += " 2) Destination Port Number : " + DPN + " / ";

			// 16������ 10������
			int DPN_10 = Integer.parseInt(DPN, 16);
			// ��Ʈ��ȣ�� ������ ���� �м�
			if (DPN_10 >= 0 && DPN_10 <= 1023) {
				System.out.print("(Well-Known Port) : ");
				r += "(Well-Known Port) : ";
				System.out.println(Port("UDP", DPN_10));
				r += Port("UDP", DPN_10) + "<br>";
			} else if (DPN_10 >= 1024 && DPN_10 <= 49151) {
				System.out.println("(Registered Port) : Organization or buisness Port");
				r += "(Registered Port) : Organization or buisness Port<br>";
			} else if (DPN_10 >= 49152 && DPN_10 <= 65535) {
				System.out.println("(Dynamic Port) : Client Port");
				r += "(Dynamic Port) : Client Port<br>";
			} else {
				System.out.println();
				r += "<br>";
			}

			// Total length �м�
			String TL = format.substring(8, 12);
			System.out.print(" 3) Total length : " + TL + " / ");
			r += " 3) Total length : " + TL + " / ";
			// 16������ 10������ ��ȯ
			int TL_10 = Integer.parseInt(TL, 16);
			System.out.println(TL_10 + " bytes : " + (TL_10 - 20) + " bytes payload");
			r += TL_10 + " bytes : " + (TL_10 - 20) + " bytes payload<br>";

			// Checksum �м�
			String Checksum = format.substring(12, 16);
			System.out.println(" 4) Checksum : " + Checksum);
			r += " 4) Checksum : " + Checksum + "<br>";

			// UDP DATA�� ���� ���!
			if (format.length() > 16) {
				// data�� ����
				int data_length = (format.length() - 16) / 2;
				System.out.println("5) Data Length : " + data_length + " bytes");
				r += "5) Data Length : " + data_length + " bytes<br>";

				// data ��
				String data = format.substring(16, format.length());
				System.out.println(" 6) Data : " + data);
				r += " 6) Data : " + data + "<br>";
			}
			// ����ó�� --> ������ ���� 65,535 ����Ʈ�� �Ѿ ���
			else if (format.length() > 65535 * 2) {
				System.out.println("�ʹ� ���� �ɼ� �����Ͱ� �߰��Ǿ����ϴ�.");
				r += "�ʹ� ���� �ɼ� �����Ͱ� �߰��Ǿ����ϴ�.<br>";
			}
		}
	}

	public static void main(String[] args) {

		// ������ �� �ޱ�
		String Ethernet_Frame = "";
		Scanner scan = new Scanner(System.in);

		while (true) {
			// ethernet frame �Է¹ޱ�
			System.out.println("Ethernet Frame�� �Է��Ͻÿ� : ");
			Ethernet_Frame = scan.nextLine();
			System.out.println();

			// �Է¹�����
			System.out.println("Frame : " + Ethernet_Frame);

			// ethernet frame �м�
			ethernet(Ethernet_Frame);
			System.out.println();
			System.out.println();
		}
	}

}