package net.floodlightcontroller.mactracker;

import java.util.Collection;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.TransportPort;
import org.projectfloodlight.openflow.types.VlanVid;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;


import net.floodlightcontroller.core.IFloodlightProviderService;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.Set;

import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;

import org.slf4j.Logger;
import  org.slf4j.LoggerFactory;
	
//MACTracker要实现两个接口 IOFMessageListener, IFloodlightModule
//将鼠标移到这两个接口名上，会显示出类中相关的接口方法实现，interface规定了类
//必须要实现的最小接口，http://www.cnblogs.com/vamei/archive/2013/03/27/2982230.html
public class MACTracker implements IOFMessageListener, IFloodlightModule {
	
	//protected的讲解可见http://www.cnblogs.com/vamei/archive/2013/03/29/2982232.html
	protected IFloodlightProviderService floodlightProvider;
	protected Set<Long> macAddresses;
	protected static Logger logger;
	@Override
	//override是检查方法重载的意思，编译器可以给你验证@Override下面的
	//方法名是否是你父类中所有的，如果没有则报错。
	public String getName() {
		// TODO Auto-generated method stub
		// return null;
		 return MACTracker.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	////Collection相当于C++里的STL
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override    ///////
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		// TODO Auto-generated method stub
		 Collection<Class<? extends IFloodlightService>> l =
			        new ArrayList<Class<? extends IFloodlightService>>();
			    l.add(IFloodlightProviderService.class);
			    return l;
	}

	@Override    ////////////  //变量初始化
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		// TODO Auto-generated method stub
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
	    macAddresses = new ConcurrentSkipListSet<Long>();
	    logger = LoggerFactory.getLogger(MACTracker.class);
	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		// TODO Auto-generated method stub
		  floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);

	}

	@Override
	//监听什么信息，这里是监听packet_in报文，具体是什么见openflow协议，谁去监听，这里是本类去监听
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		// TODO Auto-generated method stub
		//获取以太帧信息
		//二层交换机  原理 参考 http://blog.csdn.net/herostarone/article/details/8256235
		// 百度百科 http://baike.baidu.com/link?url=r7xs7ASCRIv5ssN5yh1LduU_a-_1bdQd2l8gpEWSnigDiIH1OdvITVjWwGBVC5kMW2rROfGRHCabMWzuHb05La
		 Ethernet eth =
	                IFloodlightProviderService.bcStore.get(cntx,
	                                            IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		//拿到具体的以太帧里的源MAC，交换机的二层学习机制都是通过报文的源地址和in_port来学习转发的
		//这里没有学习in_port，所以该APP只是用来记录在哪些交换机上遇到过哪些主机发来的报文，还不是二层学习交换机的配置
		//只是二层记录MAC的交换机配置，所以叫MACTracker
	        Long sourceMACHash = eth.getSourceMACAddress().getLong();
	        if (!macAddresses.contains(sourceMACHash)) {
	            macAddresses.add(sourceMACHash);
	            logger.info("MAC Address: {} seen on switch: {}",
	                    eth.getSourceMACAddress().toString(),
	                    sw.getId().toString());
	        }
	        return Command.CONTINUE;
	        
		/*
		switch (msg.getType()) {
	    case PACKET_IN:
	      
	        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
	 
	   
	        MacAddress srcMac = eth.getSourceMACAddress();
	        VlanVid vlanId = VlanVid.ofVlan(eth.getVlanID());
	 
	       
	        if (eth.getEtherType() == EthType.IPv4) {
	          
	            IPv4 ipv4 = (IPv4) eth.getPayload();
	             
	           
	            byte[] ipOptions = ipv4.getOptions();
	            IPv4Address dstIp = ipv4.getDestinationAddress();
	             
	           
	            if (ipv4.getProtocol().equals(IpProtocol.TCP)) {
	            
	                TCP tcp = (TCP) ipv4.getPayload();
	  
	          
	                TransportPort srcPort = tcp.getSourcePort();
	                TransportPort dstPort = tcp.getDestinationPort();
	                short flags = tcp.getFlags();
	                 
	      
	            } else if (ipv4.getProtocol().equals(IpProtocol.UDP)) {
	 
	                UDP udp = (UDP) ipv4.getPayload();
	  
	          
	                TransportPort srcPort = udp.getSourcePort();
	                TransportPort dstPort = udp.getDestinationPort();
	                 
	            }
	 
	        } else if (eth.getEtherType() == EthType.ARP) {
	        
	            ARP arp = (ARP) eth.getPayload();
	 
	           
	            boolean gratuitous = arp.isGratuitous();
	 
	        } else {
	          
	        }
	        break;
	    default:
	        break;
	    }
	    return Command.CONTINUE;
	    */
	}

}
