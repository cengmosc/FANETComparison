 /* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2011 University of Kansas
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Omer Hakan Karakucuk adapted from manet-routing-compare & anthocnet-sim 
   Author of original anthocnet-sim: Leon Tan <leon.arian.tan@gmail.com>
 * Author of original manet-routing-compare: Justin Rohrer <rohrej@ittc.ku.edu>
 *  
 * 
 * James P.G. Sterbenz <jpgs@ittc.ku.edu>, director
 * ResiliNets Research Group  http://wiki.ittc.ku.edu/resilinets
 * Information and Telecommunication Technology Center (ITTC)
 * and Department of Electrical Engineering and Computer Science
 * The University of Kansas Lawrence, KS USA.
 *
 * Work supported in part by NSF FIND (Future Internet Design) Program
 * under grant CNS-0626918 (Postmodern Internet Architecture),
 * NSF grant CNS-1050226 (Multilayer Network Resilience Analysis and Experimentation on GENI),
 * US Department of Defense (DoD), and ITTC at The University of Kansas.
 */
 
#include <fstream>
#include <sstream>
#include <iostream>
#include <cstdlib>
#include <sys/time.h>
#include <ctime>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ns3/object.h"
#include "ns3/ipv4-l3-protocol.h"
#include "ns3/traced-value.h"
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/ipv4-flow-classifier.h"
#include "ns3/stats-module.h"
#include "ns3/applications-module.h"

#include "ns3/aodv-module.h"
#include "ns3/anthocnet-module.h"
#include "ns3/olsr-module.h"
#include "ns3/dsdv-module.h"
#include "ns3/dsr-module.h"

#include "ns3/netanim-module.h"

#include "ns3/flow-monitor-module.h"
#include "ns3/basic-energy-source-helper.h"
#include "ns3/basic-energy-source.h"
#include "ns3/wifi-radio-energy-model.h"
#include "ns3/energy-module.h"
#include "ns3/config-store-module.h"
#include "ns3/wifi-radio-energy-model-helper.h"


using namespace ns3;
using namespace dsr;
using namespace ahn;

typedef struct SimResult {
  double pdr;
  double delay;
  double delay_jitter;
  double packet_overhead;
  double byte_overhead;
} sim_results_t;

typedef struct SimOptions {
 
  std::string routingProtocolNameShort; 
  std::string routingProtocolName;
  std::string propagationLossModelName;
  std::string mobilityModelName;
} sim_options_t;


class RoutingExperiment {
public:
  RoutingExperiment();
  void Run(uint32_t iteration);
  std::string CommandSetup(int argc, char** argv);
  
  void GetResults(sim_results_t& r);
  void PrintResults(sim_results_t& r, std::ofstream& os);
  void PrintOptions(std::ostream& os);
  void AnalyzeResults(Ptr<FlowMonitor> monitor, Time totalTime, uint32_t size);
  void GenerateDetailedResults(Ptr<Ipv4FlowClassifier> classifier, Ptr<FlowMonitor> flowmon);
  void GenerateEnergyReport(DeviceEnergyModelContainer deviceModels);
  uint32_t SetControlPort(uint32_t protocol);
  void SimulationOptionPrinter(sim_options_t& opt);
  bool GnuplotDataFileExist(const std::string& gnuplotDataFileName);
  void PrintRemainingEnergy (double oldValue, double remainingEnergy);
  void PrintTotalEnergy (double oldValue, double totalEnergy);
  
private:
  
  
  
  void IpTxTracer(Ptr<Packet const> packet, Ptr<Ipv4> ipv4, uint32_t interface);
  void IpRxTracer(Ptr<Packet const> packet, Ptr<Ipv4> ipv4, uint32_t interface);
  
  void ProgressUpdate();
  
  
  
  // State
  Ptr<SimDatabase> db;
  
  uint64_t control_packets;
  uint64_t control_bytes;
  uint64_t data_packets;
  uint64_t data_bytes;
  
  results_t result;
  uint32_t iteration;
  
  
  Ptr<UniformRandomVariable> random;
  
  void GenGnuplot (std::list<double>& values, 
                   std::string tr_name, std::string title,
                   std::string file_ext, 
                   std::string legendX, std::string legendY,
                   double gran ) const;
  
              
                   
  // Config
  
  // Simulation parameters
  Time total_time;
  uint32_t nWifis;
  uint32_t nSender;
  uint32_t nReceiver;
  
  uint32_t pWidth;
  uint32_t pHeight;
  uint32_t pDepth;
  
  uint32_t nodePause;
  uint32_t nodeMinSpeed;
  uint32_t nodeMaxSpeed;
  
  // Output parameters
  bool generate_pcap;
  double output_granularity;
  bool generate_flowmon;
  bool generate_energyreport;
  
  // Phy Layer parameters
  uint32_t phyMode;
  uint32_t lossModel;
  uint32_t mobilityModel;
  
  double txpStart;
  double txpEnd;
  
  // Mac Layer parameters
  
  // IP Layer parameters
  uint32_t protocol;
  uint32_t packetSize;
  uint32_t packetRate;
  
  uint32_t appStartBegin;
  uint32_t appStartEnd;
  
  // Blackhole configuration
  uint32_t nHoles;
  uint32_t holesStartBegin;
  uint32_t holesStartEnd;
  
  // Fuzzy configuration
  bool use_fuzzy;

  
 
  
  std::string comment;
  
};

RoutingExperiment::RoutingExperiment():
total_time(Seconds(120)),
nWifis(30),
nSender(10),
nReceiver(10),

pWidth(500),
pHeight(1500),
pDepth(1500),

nodePause(30),
nodeMinSpeed(5),
nodeMaxSpeed(20),

generate_pcap(false),
output_granularity(1.0),
generate_flowmon(false),
generate_energyreport(false),


phyMode(1),
lossModel(1),
mobilityModel(1),
txpStart(7.5),
txpEnd(7.5),

protocol(1),
packetSize(64),
packetRate(4),

appStartBegin(30),
appStartEnd(60),

nHoles(0),
holesStartBegin(30),
holesStartEnd(60),

use_fuzzy(false)

{}

std::string RoutingExperiment::CommandSetup(int argc, char** argv) {
  CommandLine cmd;
  
  // Simulation parameters
  cmd.AddValue("Time", "The total time of the experiment", this->total_time);
  
  cmd.AddValue("nWifis", 
               "The total number of nodes in this simulation", this->nWifis);
  cmd.AddValue("nSender", "The total number of sender nodes", this->nSender);
  cmd.AddValue("nReceiver", "The total number of receiver nodes", this->nReceiver);
  
  cmd.AddValue("nodePause",
               "Time in seconds a node rests after reaching waypoint", 
               this->nodePause);
  
  cmd.AddValue("nodeMinSpeed",
               "Minimal speed a node can move to next waypoint", 
               this->nodeMinSpeed);
  
  cmd.AddValue("nodeMaxSpeed",
               "Maximal speed a node can move to next waypoint", 
               this->nodeMaxSpeed);
  
  cmd.AddValue("pWidth", "Width of the simulated plane", this->pWidth);
  cmd.AddValue("pHeight", "Height of the simulated plane", this->pHeight);
  cmd.AddValue("pDepth", "Depth of the simulated plane", this->pDepth);
  
  // Output parameters
  cmd.AddValue("generatePcap", 
               "Specify, whether Pcap output should be generated", 
               this->generate_pcap);
  
  cmd.AddValue("outputGranularity",
               "How granualar the graphs generated should be (in seconds)",
               this->output_granularity);

  cmd.AddValue("generateFlowmon", 
               "Specify, whether Flowmon output should be generated", this->generate_flowmon);
  
  cmd.AddValue("generateEnergyReport", 
               "Specify, whether energy report output should be generated", this->generate_energyreport);
  

  // Phy layer parameters
  cmd.AddValue("phyMode", 
               "The physical Mode to use: 1=Dsss11Mbps; 2=Dsss1Mbps; 3=Dsss2Mbps",
               this->phyMode);
  cmd.AddValue("lossModel", "The loss model to simulate 1=Range; 2=Friis; 3=TwoRay",
               this->lossModel);

 cmd.AddValue("mobilityModel", "The mobility model to simulate 1=RandomWayPoint; 2=GaussMarkov; 3=Paparazzi",
               this->mobilityModel);
  
  cmd.AddValue("txpStart", "Antenna gain at start of transmission", this->txpStart);
  cmd.AddValue("txpEnd", "Antenna gain at end of transmission", this->txpEnd);
  
  // Mac layer parameters
  
  // IP layer parametes
  cmd.AddValue("protocol", 
               "The protocol to use: 1=AODV; 2=ANTHOCNET; 3=DSDV; 4=OLSR; 5=DSR", this->protocol);
  
  
  cmd.AddValue("packetSize", 
               "The size of the packets to be send", this->packetSize);
  cmd.AddValue("packetRate", 
               "The rate of the packets", this->packetRate);
  
  
  cmd.AddValue("appStartBegin", 
               "Begin of time window where app starts", this->appStartBegin);
  cmd.AddValue("appStartEnd", 
               "End of time window where app starts", this->appStartEnd);
  
  cmd.AddValue("nHoles", 
               "The number of blackhole nodes to introduce into the system", this->nHoles);
  cmd.AddValue("holesStartBegin", 
               "Begin of time window where blackhole mode triggers", this->holesStartBegin);
  cmd.AddValue("holesStartEnd", 
               "End of timewindow where blackhole mode triggers", this->holesStartEnd);
  
  
  cmd.AddValue("useFuzzy", 
               "Select whether to use the fuzzy system or not", this->use_fuzzy);

  
  
  cmd.AddValue("Comment", 
               "Give a short description of this simulation", this->comment);
  cmd.Parse(argc, argv);
  return "STUB";
}


void RoutingExperiment::PrintOptions(std::ostream& os) {
  
  os << "Command line options: " << std::endl;
  
  os << "Time: " << this->total_time.GetSeconds() << std::endl;
  
  os << "nWifis: " << this->nWifis << std::endl;
  os << "nSender: " << this->nSender << std::endl;
  os << "nReceiver: " << this->nReceiver << std::endl;
  
  os << "nodePause: " << this->nodePause << std::endl;
  
  os << "nodeMinSpeed: " << this->nodeMinSpeed << std::endl;
  os << "nodeMaxSpeed: " << this->nodeMaxSpeed << std::endl;
  
  os << "pWidth: " << this->pWidth << std::endl;
  os << "pHeight: " << this->pHeight << std::endl;
  os << "pDepth: " << this->pDepth << std::endl;

  os << "protocol: " << this->protocol << std::endl;
  os << "lossModel: " << this->lossModel << std::endl;
  os << "mobilityModel: " << this->mobilityModel << std::endl;
  
  os << "packetRate: "<< this->packetRate << std::endl;
  os << "packetSize: "<< this->packetSize << std::endl;
  
  os << "appStartBegin: " << this->appStartBegin << std::endl;
  os << "appStartBegin: " << this->appStartEnd << std::endl;
  
  os << "nHoles: " << this->nHoles << std::endl;
  os << "holesStartBegin: " << this->holesStartBegin << std::endl;
  os << "holesStartEnd: " << this->holesStartEnd << std::endl;
  
  os << "useFuzzy: " << this->use_fuzzy << std::endl;
  
  
}

void RoutingExperiment::GetResults(sim_results_t& r) {
  
  r.pdr = 1.0 - this->result.droprate_total_avr;
  r.delay = this->result.end_to_end_delay_total_avr;
  r.delay_jitter = this->result.total_average_delay_jitter;
  r.packet_overhead = (double) this->control_packets / this->data_packets;
  r.byte_overhead = (double) this->control_bytes / this->data_bytes;
  
  
}

void RoutingExperiment::PrintResults(sim_results_t& r, std::ofstream& os) {
  os << "PDR, Delay, Delay_Jitter, Packet_Overhead, Byte_Overhead" << std::endl;
  os << r.pdr << ", " << r.delay << ", " << r.delay_jitter << ", "  << r.packet_overhead << ", " << r.byte_overhead << std::endl;
}

void RoutingExperiment::ProgressUpdate() {
  std::cout << "Experiment: " << this->iteration + 1 << " "
    << Simulator::Now().GetSeconds()
    << "s/" << total_time.GetSeconds()
    << "s passed (" 
    << ((double)Simulator::Now().GetSeconds() / total_time.GetSeconds()) * 100
    << "%)" << std::endl; 
    
  
  Simulator::Schedule(Seconds(1), &RoutingExperiment::ProgressUpdate, this);
}



// Trace functions
// Trace function for remaining energy at node.
void RoutingExperiment::PrintRemainingEnergy (double oldValue, double remainingEnergy)
{
  NS_LOG_UNCOND (Simulator::Now ().GetSeconds ()
                 << "s Current remaining energy = " << remainingEnergy << "J");
}

// Trace function for total energy consumption at node.
void RoutingExperiment::PrintTotalEnergy (double oldValue, double totalEnergy)
{
  NS_LOG_UNCOND (Simulator::Now ().GetSeconds ()
                 << "s Total energy consumed by radio = " << totalEnergy << "J");
}


void RoutingExperiment::GenerateEnergyReport(DeviceEnergyModelContainer deviceModels)
{
          
          
          sim_options_t opt;
          SimulationOptionPrinter(opt);
          std::string gnuplotEnergyDataFileName=opt.routingProtocolNameShort+"GnuplotEnergyDataFile.csv";
	  double energyConsumed = 0.0;
	  double TotalEnergyConsumed=0.0;
	  double AvgEnergyConsumed=0.0;
	  uint32_t nodeNumber = 1;
	  if(this->generate_energyreport)
	  {		
	          
		  for (DeviceEnergyModelContainer::Iterator iter = deviceModels.Begin (); iter != deviceModels.End (); iter ++)
		    {
		       energyConsumed = (*iter)->GetTotalEnergyConsumption ();
		       TotalEnergyConsumed += energyConsumed;
		       AvgEnergyConsumed = TotalEnergyConsumed / nodeNumber;

		       std::cout<<" Total energy consumed by node " << nodeNumber << " is " << energyConsumed << "J and total energy consumed by network is "<< TotalEnergyConsumed<< " J and "<< "average energy consumed by network is "  << AvgEnergyConsumed<< " J!\n";
		       nodeNumber++;
		       NS_ASSERT (energyConsumed <= 100.0);
		    }
		  
	   }
	   
	   
    
    std::cout << gnuplotEnergyDataFileName << std::endl;
    gnuplotEnergyDataFileName ="../GnuplotData/"+ gnuplotEnergyDataFileName;
    std::cout << gnuplotEnergyDataFileName << std::endl;
    bool gnuplotDataFileExist = GnuplotDataFileExist(gnuplotEnergyDataFileName);
    
    if(!gnuplotDataFileExist)
    {
    
      std::cout << "File Not Exists" << std::endl;
      std::ofstream gnuplotDataFileStream(gnuplotEnergyDataFileName);
      gnuplotDataFileStream << "Node Number"  << ","<<"Node Energy Consumption J"<< ","<< " Total Energy Consumption J"<< ","<< "Average Energy Consumption J" <<"\n";
      gnuplotDataFileStream << this->nWifis <<"," << energyConsumed << "," <<  TotalEnergyConsumed <<  "," << AvgEnergyConsumed <<  "," << "\n";
      gnuplotDataFileStream.close();
      std::cout << "Gnuplot energy data written in to "+ gnuplotEnergyDataFileName << std::endl;
    
      
    }
    else
    {
       std::cout << "File Exist!" << std::endl;
       std::ofstream appendGnuplotDataStream;
       appendGnuplotDataStream.open(gnuplotEnergyDataFileName, std::ofstream::out | std::ofstream::app); 
       appendGnuplotDataStream << this->nWifis <<"," << energyConsumed << "," <<  TotalEnergyConsumed <<  "," << AvgEnergyConsumed <<  "," << "\n";
       appendGnuplotDataStream.close();
       
       std::cout << "Gnuplot data appended to "+ gnuplotEnergyDataFileName << std::endl;      
       
    
    }    
  
 


}

// All the tracers
void RoutingExperiment::IpTxTracer(Ptr<Packet const> cpacket, Ptr<Ipv4> ipv4, 
                                   uint32_t interface) {
  
  //std::cout << "Packet txd: " << *cpacket << std::endl; 
  
  Ptr<Packet> packet = cpacket->CreateFragment(0, cpacket->GetSize());
  
  Ipv4Header ipheader;
  UdpHeader udpheader;
  SimPacketHeader simheader;
  
  packet->RemoveHeader(ipheader);
  packet->RemoveHeader(udpheader);
  
  if (udpheader.GetSourcePort() != 49192) {
    
    control_packets++;
    control_bytes += cpacket->GetSize() + 36;
    
  }
  else {
    
    packet->RemoveHeader(simheader);
    uint64_t seqno = this->db->CreateNewTransmission(
      ipv4->GetAddress(interface, 0).GetLocal());
    this->db->RegisterTx(seqno, simheader.GetSeqno(), packet->GetSize());
    
  }
  
}

void RoutingExperiment::IpRxTracer(Ptr<Packet const> cpacket, Ptr<Ipv4> ipv4, 
                                   uint32_t interface) {
  
  Ptr<Packet> packet = cpacket->CreateFragment(0, cpacket->GetSize());
  
  Ipv4Header ipheader;
  UdpHeader udpheader;
  SimPacketHeader simheader;
  
  packet->RemoveHeader(ipheader);
  packet->RemoveHeader(udpheader);
  
  
  if (udpheader.GetSourcePort() != 49192) {
    
  }
  else {
    
    Ptr<Ipv4L3Protocol> l3 = ipv4->GetObject<Ipv4L3Protocol>();
    Ipv4Address this_node = l3->GetAddress(1, 0).GetLocal();
    
    if (ipheader.GetDestination() == this_node) {
      data_packets++;
      data_bytes += cpacket->GetSize() + 36;
    }
    
    packet->RemoveHeader(simheader);
    
    this->db->RegisterRx(simheader.GetSeqno(), 
                         ipv4->GetAddress(interface, 0).GetLocal());
    
  }
  
}


uint32_t RoutingExperiment::SetControlPort(uint32_t protocol)
{
	uint32_t controlPort=0;
	
	if(protocol == 1)
	{
	  //AODV control port 654
	  controlPort = 654;
	
	}
	
	else if(protocol == 2)
	{
	   //AntHocNet control port 5555
	   controlPort=5555;
	}
	
	else if(protocol == 3)
	{
	   //DSDV control port 
	   controlPort = 269;
	}
	
	else if(protocol == 4)
	{
	    //OLSR control port
	    controlPort = 698;
	}
	
	else if(protocol == 5)
	{
	    //DSR control port
	    controlPort = 9;
	}
	
	else{
		std::cout<<"No such protocol supported!!!"<< std::endl;
		controlPort = 0;
	}
	
	return controlPort;

}

bool RoutingExperiment::GnuplotDataFileExist(const std::string& gnuplotDataFileName)
{
	struct stat buffer;   
        return (stat (gnuplotDataFileName.c_str(), &buffer) == 0);
}
void RoutingExperiment::SimulationOptionPrinter(sim_options_t& opt)
{

	switch (this->protocol) 
	{
	    case 1:
	      opt.routingProtocolNameShort = "AODVRoutingProtocol";
	      opt.routingProtocolName = "AODV Routing Protocol";
	      break;
	    case 2:
	      opt.routingProtocolNameShort = "AntHocNetRoutingProtocol";
	      opt.routingProtocolName = "AntHocNet Routing Protocol";
	      break;
	    case 3:
	      opt.routingProtocolNameShort = "DSDVRoutingProtocol";
	      opt.routingProtocolName = "DSDV Routing Protocol";
	      break;
	    case 4:
	      opt.routingProtocolNameShort = "OLSRRoutingProtocol";
	      opt.routingProtocolName = "OLSR Routing Protocol";
	      break;
	    case 5:
	      opt.routingProtocolNameShort = "DSRRoutingProtocol";
	      opt.routingProtocolName = "DSR Routing Protocol";
	    default:
	      NS_FATAL_ERROR ("No such routing protocol supported");
	      break;
  	}
	
	switch (this->lossModel) 
	{
	    case 1:
	      opt.propagationLossModelName = "Range Propagation Loss Model";
	      break;
	    case 2:
	      opt.propagationLossModelName = "Friis Propagation Loss Model";
	      break;
	    case 3:
	      opt.propagationLossModelName = "Two Ray Ground Propagatşon Loss Model";
	      break;
	    default:
	      NS_FATAL_ERROR ("No such propagation loss model supported");
	      break;
  	}
	
	switch (this->mobilityModel) 
	{
	    case 1:
	      opt.mobilityModelName = "Random Waypoint Mobility Model";
	      break;
	    case 2:
	      opt.mobilityModelName = "Gauss Markov Mobility Model";
	      break;
	    case 3:
	      opt.mobilityModelName = "PAPARAZZI Mobility Model";
	      break;
	    default:
	      NS_FATAL_ERROR ("No such mobility model supported");
	      break;
  	}


}

void RoutingExperiment::GenerateDetailedResults(Ptr<Ipv4FlowClassifier> classifier, Ptr<FlowMonitor> flowmon)
{
  
 
  sim_options_t opt;
  SimulationOptionPrinter(opt);
  std::string gnuplotDataFileName=opt.routingProtocolNameShort+"GnuplotDataFile.csv";
  std::string fuzzylogicUsage;
  if(this->use_fuzzy)
  {
        fuzzylogicUsage="Fuzzylogic Used!";
  }
  else
  {
  	fuzzylogicUsage="Fuzzylogic Not Used!";
  }
  uint32_t controlPort= SetControlPort(this->protocol);
  const uint32_t UDP_PORT_NUMBER = 17;	
  std::ofstream resultsFile("SimulationResults.csv");   
  double TxBytes = 0;
  double RxBytes = 0;
  double RoutingOverhead = 0;
  double PacketOverhead = 0;
  double ByteOverhead = 0; 
  double FlowThroughput = 0;
  double TotalThroughput = 0;
  double AvgThroughput = 0;
  Time Jitter;
  Time Delay;
  uint32_t SentPackets = 0;
  uint32_t ReceivedPackets = 0;
  uint32_t TimesForwarded = 0;
  double TotalHopCount= 0; 
  double HopCount = 0;
  double AvgHopCount = 0;
  uint32_t LostPackets = 0;
  double PacketLossRatio = 0;
  double PacketDeliveryRatio = 0;
  double Goodput = 0 ;
  double FlowLoad = 0;
  double TotalLoad = 0;
  double AvgLoad = 0;
  uint32_t FlowCount = 0;
 
  std::map<FlowId, FlowMonitor::FlowStats> stats = flowmon->GetFlowStats ();

  for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator iter = stats.begin (); iter != stats.end (); ++iter)
   {  
	  
	  Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow (iter->first);
	  
	  std::cout<<"----Flow ID:" <<iter->first<<"\n";
	  std::cout<< "Source Address: "<< t.sourceAddress << " Destination Address: " << t.destinationAddress << "\n";
	        if (t.protocol == UDP_PORT_NUMBER  && (t.destinationPort == controlPort || t.sourcePort == controlPort))
	        {
	        	RxBytes += iter->second.rxBytes;
	        	TxBytes += iter->second.txBytes;
	        
	        }
             
	  std::cout<<"Sent Packets=" <<iter->second.txPackets<<"\n";
	  std::cout<<"Received Packets =" <<iter->second.rxPackets<<"\n";
	  std::cout<< "Times Forwarded =" << iter->second.timesForwarded <<"\n";
	  std::cout<< "Hop Count =" << iter->second.timesForwarded + 1 <<"\n";
	  std::cout<<"Lost Packets =" <<iter->second.txPackets-iter->second.rxPackets<<"\n";
	  std::cout<<"Packet delivery ratio =" <<iter->second.rxPackets*100/iter->second.txPackets << "%"<<"\n";
	  std::cout<<"Packet loss ratio =" << (iter->second.txPackets-iter->second.rxPackets)*100/iter->second.txPackets << "%"<<"\n";
	  std::cout<<"Delay =" <<iter->second.delaySum<<"\n";
	  std::cout<<"Jitter =" <<iter->second.jitterSum<<"\n";
	  std::cout<<"Flow Throughput =" <<iter->second.rxBytes * 8.0/(iter->second.timeLastRxPacket.GetSeconds()-iter->second.timeFirstTxPacket.GetSeconds())/1024<<"Kbps"<<"\n";
	  std::cout<<"NetWork Load =" <<iter->second.rxBytes * 8.0 /(iter->second.timeLastRxPacket.GetSeconds()-iter->second.timeFirstTxPacket.GetSeconds())<<"bps"<<"\n";
	  std::cout<<"Ports Used By Flow ID = " << iter->first << " are " << t.sourcePort << ", " << t.destinationPort  <<"\n";
	  std::cout<<"Flow Start Time is " << iter->second.timeFirstTxPacket.GetSeconds()<<" s of simulation and Flow End Time is " << iter->second.timeLastRxPacket.GetSeconds()<< " s of simulation"  <<"\n";
	  
	  TimesForwarded = TimesForwarded +(iter->second.timesForwarded);
	  HopCount = iter->second.timesForwarded + 1;
	  SentPackets = SentPackets +(iter->second.txPackets);
	  ReceivedPackets = ReceivedPackets + (iter->second.rxPackets);
	  LostPackets = LostPackets + (iter->second.txPackets-iter->second.rxPackets);
	  FlowThroughput = iter->second.rxBytes * 8.0/(iter->second.timeLastRxPacket.GetSeconds()-iter->second.timeFirstTxPacket.GetSeconds())/1024;
	  TotalThroughput += FlowThroughput;
	  FlowLoad = iter->second.rxBytes * 8.0/(iter->second.timeLastRxPacket.GetSeconds()-iter->second.timeFirstTxPacket.GetSeconds());
	  TotalLoad += FlowLoad;
	   
	  Delay = Delay + (iter->second.delaySum);
	  Jitter = Jitter + (iter->second.jitterSum);
	  TotalHopCount += HopCount;
	  RoutingOverhead = RxBytes + TxBytes;
	  PacketOverhead = (double) this->control_packets / this->data_packets;
          ByteOverhead= (double) this->control_bytes / this->data_bytes;
	  FlowCount = FlowCount +1 ;
    }
  AvgHopCount = TotalHopCount / FlowCount;
  AvgThroughput = TotalThroughput / FlowCount;
  PacketLossRatio = ((LostPackets*100)/SentPackets);
  PacketDeliveryRatio = ((ReceivedPackets*100)/SentPackets);
  Goodput = (ReceivedPackets * 8) / this-> total_time.GetSeconds();
  AvgLoad = TotalLoad / FlowCount;
  std::cout<<"--------Summary of Simulation Options and Results----------"<<std::endl;
  
  std::cout<<"--------Simulation Options----------"<<std::endl;
  std::cout << "Simulation Duration: " << this->total_time.GetSeconds() <<" s" <<std::endl;
  std::cout << "Number of Nodes: " << this->nWifis << std::endl;
  std::cout << "Number of Sender Nodes: " << this->nSender << std::endl;
  std::cout << "Number of Receiver Nodes: " << this->nReceiver << std::endl;
  std::cout<< "Time to Wait in Waypoint: " << this->nodePause << " s" <<std::endl;
  std::cout << "Minimum Node Speed: " << this->nodeMinSpeed << " m/s" <<std::endl;
  std::cout  << "Maximum Node Speed: " << this->nodeMaxSpeed << " m/s" << std::endl;
  std::cout << "Width of Simulation Space: " << this->pWidth << " m" << std::endl; 
  std::cout << "Height of Simulation Space: " << this->pHeight << " m" <<  std::endl;
  std::cout << "Depth of Simulation Space: " << this->pHeight <<  " m" << std::endl;
  std::cout<< "Routing Protocol: " << opt.routingProtocolName << std::endl;
  std::cout << "Propagation Loss Model: " << opt.propagationLossModelName << std::endl;
  std::cout << "Mobility Model: " << opt.mobilityModelName << std::endl;
  std::cout << "Packet Rate: "<< this->packetRate <<  " p/s" << std::endl;
  std::cout << "Packet Size: "<< this->packetSize <<  " bytes" << std::endl;
  std::cout << "Start Time of Transmission: " << this->appStartBegin <<   " s" << std::endl;
  std::cout << "End Time of Transmission: " << this->appStartEnd <<  " s" <<  std::endl;
  std::cout << "Number of Blackholes: " << this->nHoles <<  " s" << std::endl;
  std::cout << "Start Time of Blackhole Creation: " << this->holesStartBegin <<  " s" <<  std::endl;
  std::cout << "End Time of Blackhole Creation: " << this->holesStartEnd <<  " s" << std::endl;
  std::cout << "Fuzzylogic Usage: " << fuzzylogicUsage << std::endl;

  std::cout<<"--------Simulation Results----------"<<std::endl;
  std::cout<<"Total Sent Packets  = " << SentPackets <<std::endl; 
  std::cout<<"Total Received Packets = " << ReceivedPackets <<std::endl;
  std::cout<<"Total Lost Packets = " << LostPackets <<std::endl;
  std::cout<<"Packet Loss Ratio = " << ((LostPackets*100)/SentPackets)<< "%" <<std::endl;
  std::cout<<"Packet Delivery Ratio = " << ((ReceivedPackets*100)/SentPackets)<< "%" <<std::endl;
  std::cout<<"Average Throughput = " << AvgThroughput<< "Kbps" <<std::endl;
  std::cout<<"Average Hop Count = " << AvgHopCount <<std::endl;
  std::cout<<"Routing Overhead = " << RoutingOverhead << " bytes"<<std::endl;
  std::cout<<"Packet Overhead = " << PacketOverhead <<std::endl;
  std::cout<<"Byte Overhead = " << ByteOverhead << " bytes"<<std::endl;
  std::cout<<"End to End Delay = " << Delay <<std::endl;
  std::cout<<"End to End Jitter Delay = " << Jitter <<std::endl;
  std::cout<<"Goodput = " << Goodput << " bits/s" <<std::endl;
  std::cout<<"Average Network Load = " << AvgLoad << " bps" <<std::endl;
  std::cout<<"Total Flow Count = " << FlowCount <<std::endl;
  
  
  // Output the overall results to the CSV
    resultsFile << "Simulation Duration"  << "," <<"Number Of Nodes"<< ","<< "Number of Sender Nodes"<< ","<< "Number of Receiver Nodes"<< ","<< "Time to Wait in Waypoint"<< ","<< "Minimum Node Speed"<< ","<< "Maximum Node Speed"<< ","<< "Width of Simulation Space" << ","<< " Height of Simulation Space" << ","<< " Depth of Simulation Space" << ","<< "Routing Protocol Name " << ","<< " Propagation Loss Model Name" << ","<< " Mobility Model Name" << ","<<  " Packet Rate" << ","<< " Packet Size" << ","<< " Start Time of Transmission" << ","<< " End Time of Transmission" << ","<< " Number of Blackholes" << ","<< " Start Time of Blackhole Creation" << ","<< " End Time of Blackhole Creation " << ","<< " Fuzzylogic Usage" << "," <<     "Total Sent Packets"<< ","<< "Total Received Packets" << ","<< "Total Lost Packets"<< ","<< "Packet Loss Ratio  %"<< ","<<"Packet Delivery Ratio %"<< ","<< "Average Throughput Kbps"<< "," << "Average Hop Count" <<","<< "Routing Overhead bytes"<<","<< "Packet Overhead" <<","<< "Byte Overhead" <<","<<"End to End Delay second"<< ","<<"End to End Jitter Delay second"  <<","<<"Goodput bits/second"  <<","<< "Average Network Load" << "," <<"Total Flow Count"  <<"\n";
    
    resultsFile << this->total_time.GetSeconds() <<"," << this->nWifis << "," <<  this->nSender <<  "," << this->nReceiver <<  "," <<  this->nodePause <<  "," << this->nodeMinSpeed << "," <<  this->nodeMaxSpeed << "," <<  this->pWidth <<  "," << this->pHeight << "," <<  this->pDepth << "," << opt.routingProtocolName <<  "," << opt.propagationLossModelName <<  "," << opt.mobilityModelName << "," <<  this->packetRate <<  "," << this->packetSize <<  "," <<  this->appStartBegin << "," <<  this->appStartEnd <<  "," << this->nHoles << "," << this->holesStartBegin << "," <<  this->holesStartEnd << "," << fuzzylogicUsage << "," << SentPackets << "," << ReceivedPackets << "," << LostPackets << "," << PacketLossRatio << "," << PacketDeliveryRatio<< ","<< AvgThroughput<<"," <<AvgHopCount<<","<< RoutingOverhead <<"," << PacketOverhead <<","<<ByteOverhead <<","<< Delay<< "," << Jitter<<","<< Goodput <<","<< AvgLoad << "," << FlowCount<<"\n";

    resultsFile.close();
    
    std::cout << "Detailed results of simulation written to SimulationResults.csv" << std::endl;
    std::cout << gnuplotDataFileName << std::endl;
    gnuplotDataFileName ="../GnuplotData/"+ gnuplotDataFileName;
    std::cout << gnuplotDataFileName << std::endl;
    bool gnuplotDataFileExist = GnuplotDataFileExist(gnuplotDataFileName);
    
    if(!gnuplotDataFileExist)
    {
    
      std::cout << "File Not Exists" << std::endl;
      std::ofstream gnuplotDataFileStream(gnuplotDataFileName);
      gnuplotDataFileStream << "Simulation Duration"  << ","<<"Number Of Nodes"<< ","<< "Number of Sender Nodes"<< ","<< "Number of Receiver Nodes"<< ","<< "Time to Wait in Waypoint"<< ","<< "Minimum Node Speed"<< ","<< "Maximum Node Speed"<< ","<< "Width of Simulation Space" << ","<< " Height of Simulation Space" << ","<< " Depth of Simulation Space" << ","<< "Routing Protocol Name " << ","<< " Propagation Loss Model Name" << ","<< " Mobility Model Name" << ","<<  " Packet Rate" << ","<< " Packet Size" << ","<< " Start Time of Transmission" << ","<< " End Time of Transmission" << ","<< " Number of Blackholes" << ","<< " Start Time of Blackhole Creation" << ","<< " End Time of Blackhole Creation " << ","<< " Fuzzylogic Usage" << "," <<     "Total Sent Packets"<< ","<< "Total Received Packets" << ","<< "Total Lost Packets"<< ","<< "Packet Loss Ratio  %"<< ","<<"Packet Delivery Ratio %"<< ","<< "Average Throughput Kbps"<< "," << "Average Hop Count" <<","<< "Routing Overhead bytes"<<","<< "Packet Overhead" <<","<< "Byte Overhead" <<","<<"End to End Delay second"<< ","<<"End to End Jitter Delay second"  <<","<<"Goodput bits/second"  <<","<< "Average Network Load" << "," << "Total Flow Count"  <<"\n";
    
    gnuplotDataFileStream <<this->total_time.GetSeconds() <<"," << this->nWifis << "," <<  this->nSender <<  "," << this->nReceiver <<  "," <<  this->nodePause <<  "," << this->nodeMinSpeed << "," <<  this->nodeMaxSpeed << "," <<  this->pWidth <<  "," << this->pHeight << "," <<  this->pDepth << "," << opt.routingProtocolName <<  "," << opt.propagationLossModelName <<  "," << opt.mobilityModelName << "," <<  this->packetRate <<  "," << this->packetSize <<  "," <<  this->appStartBegin << "," <<  this->appStartEnd <<  "," << this->nHoles << "," << this->holesStartBegin << "," <<  this->holesStartEnd << "," << fuzzylogicUsage << "," << SentPackets << "," << ReceivedPackets << "," << LostPackets << "," << PacketLossRatio << "," << PacketDeliveryRatio<< ","<< AvgThroughput<<"," <<AvgHopCount<<","<< RoutingOverhead <<"," << PacketOverhead <<","<<ByteOverhead <<","<< Delay<< "," << Jitter<<","<< Goodput <<","<< AvgLoad <<"," << FlowCount<<"\n";

    gnuplotDataFileStream.close();
    std::cout << "Gnuplot data written in to "+ gnuplotDataFileName << std::endl;
    
      
    }
    else
    {
       std::cout << "File Exist!" << std::endl;
       std::ofstream appendGnuplotDataStream;
       appendGnuplotDataStream.open(gnuplotDataFileName, std::ofstream::out | std::ofstream::app); 
       
       appendGnuplotDataStream << this->total_time.GetSeconds() <<"," << this->nWifis << "," <<  this->nSender <<  "," << this->nReceiver <<  "," <<  this->nodePause <<  "," << this->nodeMinSpeed << "," <<  this->nodeMaxSpeed << "," <<  this->pWidth <<  "," << this->pHeight << "," <<  this->pDepth << "," << opt.routingProtocolName <<  "," << opt.propagationLossModelName <<  "," << opt.mobilityModelName << "," <<  this->packetRate <<  "," << this->packetSize <<  "," <<  this->appStartBegin << "," <<  this->appStartEnd <<  "," << this->nHoles << "," << this->holesStartBegin << "," <<  this->holesStartEnd << "," << fuzzylogicUsage << "," << SentPackets << "," << ReceivedPackets << "," << LostPackets << "," << PacketLossRatio << "," << PacketDeliveryRatio<< ","<< AvgThroughput<<"," <<AvgHopCount<<","<< RoutingOverhead <<"," << PacketOverhead <<","<<ByteOverhead <<","<< Delay<< "," << Jitter<<","<<Goodput<<","<< AvgLoad << "," << FlowCount<<"\n";
       
       appendGnuplotDataStream.close();
       
       std::cout << "Gnuplot data appended to "+ gnuplotDataFileName << std::endl;      
       
    
    }    
}


void RoutingExperiment::AnalyzeResults(Ptr<FlowMonitor> monitor, Time totalTime, uint32_t size)
{
    std::ofstream resultsFile("results.csv");
    double totalTimeDouble= totalTime.GetDouble();
    double totalPacketsSent = 0;
    double totalPacketsReceived = 0;
    double totalPacketsLost= 0;
    double totalDelay = 0;
    double totalJitter = 0;
    double totalThroughput = 0;
    int flowCount = 0;

    // Iterate through all flows and collect metrics
    for (const auto& flow : monitor->GetFlowStats())
    {
        totalPacketsSent += flow.second.txPackets;     // Total packets sent
        totalPacketsReceived += flow.second.rxPackets;  // Total packets received
        totalDelay += flow.second.delaySum.GetSeconds(); // Total delay
        totalJitter += flow.second.jitterSum.GetSeconds(); //Total jitter
        totalPacketsLost +=flow.second.txPackets-flow.second.rxPackets; //Total packets lost
        // Calculate throughput for this flow in kbps
        double flowThroughput = (flow.second.rxPackets * 1024 * 8) / (totalTimeDouble * 1000); 
        totalThroughput += flowThroughput;
        flowCount++;
    }

    // Calculate overall PDR
    double overallPDR = (totalPacketsSent > 0) ? (totalPacketsReceived / totalPacketsSent) * 100 : 0;

    // Calculate average throughput per flow
    double averageThroughput = (flowCount > 0) ? (totalThroughput / flowCount) : 0;

    // Calculate overall end-to-end delay (average per received packet)
    double overallEndToEndDelay = (totalPacketsReceived > 0) ? (totalDelay / totalPacketsReceived) : 0;
    
    

    // Output the overall results to the CSV
    resultsFile << "Total Packets Lost"<< ","<< "Packet Delivery Ratio (%) " <<","<< "Average Throughput (Kbps)"<< ","<< "End to End Delay (Second)"<< ","<<"Total Jitter (Second)"  <<"\n";
    resultsFile << totalPacketsLost << "," << overallPDR << "," << averageThroughput << "," << overallEndToEndDelay << totalJitter <<"\n";

    resultsFile.close();
    std::cout << "Overall results written to results.csv\n";
}

void RoutingExperiment::Run(uint32_t iteration) {
  this->iteration = iteration;
  
  
  std::string tr_name = "anthocnet-sim";
  Packet::EnablePrinting();
  
  random = CreateObject<UniformRandomVariable>();
  
  // Create the nodes
  NodeContainer adhocNodes;
  adhocNodes.Create(this->nWifis);
  
  // Setting up the wifi
  
  // Set up the phy mode
  std::string phy_mode_string;
  switch (this->phyMode) {
    case 1:
      phy_mode_string = "DsssRate11Mbps";
      break;
    case 2:
      phy_mode_string = "DsssRate1Mbps";
      break;
    case 3:
      phy_mode_string = "DsssRate2Mbps";
      break;
    default:
      NS_FATAL_ERROR ("Phy mode not supported");
      break;
  }
  Config::SetDefault("ns3::WifiRemoteStationManager::NonUnicastMode",
                     StringValue (phy_mode_string));
  
  WifiHelper wifi;
  wifi.SetStandard(WIFI_PHY_STANDARD_80211b);
  
  YansWifiPhyHelper wifiPhy =  YansWifiPhyHelper::Default ();
  YansWifiChannelHelper wifiChannel;
  wifiChannel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
  
  std::string loss_model_string;
  switch (this->lossModel){
    case 1:
      loss_model_string = "ns3::RangePropagationLossModel";
      break;
    case 2:
      loss_model_string = "ns3::FriisPropagationLossModel";
      break;
    case 3:
      Config::SetDefault("ns3::TwoRayGroundPropagationLossModel::HeightAboveZ", 
                     DoubleValue(1.2));
      loss_model_string = "ns3::TwoRayGroundPropagationLossModel";
      break;
    default:
      NS_FATAL_ERROR ("Loss model not supported");
      break;
  }
  
  wifiChannel.AddPropagationLoss(loss_model_string);
  wifiPhy.SetChannel(wifiChannel.Create());
  
  WifiMacHelper wifiMac;
  wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                "DataMode", StringValue (phy_mode_string),
                                "ControlMode", StringValue (phy_mode_string));

  wifiPhy.Set ("TxPowerStart", DoubleValue (this->txpStart));
  wifiPhy.Set ("TxPowerEnd", DoubleValue (this->txpEnd));
  
  // Install wifi on the nodes
  wifiMac.SetType ("ns3::AdhocWifiMac");
  NetDeviceContainer adhocDevices = wifi.Install(wifiPhy, wifiMac, adhocNodes);
  
  
  // Set up plane and mobility
  MobilityHelper mobilityAdhoc;
  

  // used to get consistent mobility across scenarios
  int64_t streamIndex = 100 * iteration; 
  
  std::stringstream ssXpos, ssYpos, ssZpos;
  ssXpos << "ns3::UniformRandomVariable[Min=0.0|Max=" << this->pWidth << "]";
  ssYpos << "ns3::UniformRandomVariable[Min=0.0|Max=" << this->pHeight << "]";
  ssZpos << "ns3::UniformRandomVariable[Min=0.0|Max=" << this->pDepth << "]";
  
  
  ObjectFactory pos;
  
if (mobilityModel==1) 
        {
             
            pos.SetTypeId ("ns3::RandomRectanglePositionAllocator");
            pos.Set ("X", StringValue (ssXpos.str()));
            pos.Set ("Y", StringValue (ssYpos.str()));
           
            std::stringstream ssSpeed;
            ssSpeed << "ns3::UniformRandomVariable[Min=0.0|Max=" << nodeMaxSpeed << "]";
            std::stringstream ssPause;
            ssPause << "ns3::ConstantRandomVariable[Constant=" << nodePause << "]";
            Ptr<PositionAllocator> taPositionAlloc = pos.Create()->GetObject<PositionAllocator>();
            streamIndex += taPositionAlloc->AssignStreams(streamIndex);
           
            mobilityAdhoc.SetMobilityModel("ns3::RandomWaypointMobilityModel",
                                       "Speed",
                                       StringValue(ssSpeed.str()),
                                       "Pause",
                                       StringValue(ssPause.str()),
                                       "PositionAllocator",
                                       PointerValue(taPositionAlloc));
            mobilityAdhoc.SetPositionAllocator(taPositionAlloc);
        }

                                   
    else if (mobilityModel==2) 
            {
        
                pos.SetTypeId("ns3::RandomBoxPositionAllocator");
                pos.Set ("X", StringValue (ssXpos.str()));
                pos.Set ("Y", StringValue (ssYpos.str()));
                pos.Set ("Z", StringValue(ssZpos.str()));
                
                mobilityAdhoc.SetMobilityModel ("ns3::GaussMarkovMobilityModel",
                                              "Bounds", BoxValue (Box (0, pWidth, 0, pHeight, 0, pDepth)),
                                              "TimeStep", TimeValue (Seconds (0.5)),
                                              "Alpha", DoubleValue (0.85),
                                              "MeanVelocity", StringValue ("ns3::UniformRandomVariable[Min=800|Max=1200]"),
                                              "MeanDirection", StringValue ("ns3::UniformRandomVariable[Min=0|Max=6.283185307]"),
                                              "MeanPitch", StringValue ("ns3::UniformRandomVariable[Min=0.05|Max=0.05]"),
                                              "NormalVelocity", StringValue ("ns3::NormalRandomVariable[Mean=0.0|Variance=0.0|Bound=0.0]"),
                                              "NormalDirection", StringValue ("ns3::NormalRandomVariable[Mean=0.0|Variance=0.2|Bound=0.4]"),
                                              "NormalPitch", StringValue ("ns3::NormalRandomVariable[Mean=0.0|Variance=0.02|Bound=0.04]"));
            }
                                      
                                     
    else if (mobilityModel==3) 
            {
        
                pos.SetTypeId("ns3::RandomBoxPositionAllocator");
                pos.Set ("X", StringValue (ssXpos.str()));
                pos.Set ("Y", StringValue (ssYpos.str()));
                pos.Set ("Z", StringValue(ssZpos.str()));
                             
                mobilityAdhoc.SetMobilityModel ("ns3::PaparazziMobilityModel",
			                                    "Radius", StringValue ("10"),
			                                    "Bounds", BoxValue (Box (0, pWidth, 0, pHeight, 0, pDepth)));
			}
    else
      {  
         NS_FATAL_ERROR("No such mobility model implemented:" << mobilityModel);
     
      }
  mobilityAdhoc.Install(adhocNodes);
  streamIndex += mobilityAdhoc.AssignStreams(adhocNodes, streamIndex);
  NS_UNUSED (streamIndex); 
  
  
DeviceEnergyModelContainer deviceModels;
if (this->generate_energyreport)
{

  /////////////-------- Energy Source and Device Energy Model  configuration -----------------------------------

	  /** Energy Model **/
	  /***************************************************************************/
	  /* energy source */
	  BasicEnergySourceHelper basicSourceHelper;
	  // configure energy source
	  basicSourceHelper.Set ("BasicEnergySourceInitialEnergyJ", DoubleValue (100.0));
	  // install source
	  EnergySourceContainer sources = basicSourceHelper.Install (adhocNodes);
	  /* device energy model */
	  WifiRadioEnergyModelHelper radioEnergyHelper;
	  // configure radio energy model
	  radioEnergyHelper.Set ("TxCurrentA", DoubleValue (0.0174));
	  // install device model
	  deviceModels = radioEnergyHelper.Install (adhocDevices, sources);
	  /***************************************************************************/

	  
	  /** connect energy trace sources **/
	  /***************************************************************************/
	  // all sources are connected to node 1
	  // energy source
	  Ptr<BasicEnergySource> basicSourcePtr = DynamicCast<BasicEnergySource> (sources.Get (1));
	  basicSourcePtr->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RoutingExperiment::PrintRemainingEnergy, this));
	  // device energy model
	  Ptr<DeviceEnergyModel> basicRadioModelPtr =
	  basicSourcePtr->FindDeviceEnergyModels ("ns3::WifiRadioEnergyModel").Get (0);
	  NS_ASSERT (basicRadioModelPtr != NULL);
	  basicRadioModelPtr->TraceConnectWithoutContext ("TotalEnergyConsumption",MakeCallback (&RoutingExperiment::PrintTotalEnergy, this));
	  /***************************************************************************/

}

  
  // Set up the IP layer routing protocol
  AodvHelper aodv;
  AntHocNetHelper ahn;
  DsdvHelper dsdv;
  OlsrHelper olsr;
  DsrHelper dsr;
  DsrMainHelper dsrMain;

  Ipv4ListRoutingHelper list;
  InternetStackHelper internet;
  
  switch (this->protocol) {
    case 1:
      list.Add (aodv, 100);
      break;
    case 2:
      list.Add (ahn, 100);
      break;
    case 3:
      list.Add (dsdv, 100);
      break;
    case 4:
      list.Add (olsr, 100);
      break;
    case 5:
      
      break;
    default:
      NS_FATAL_ERROR ("No such protocol supported!");
      break;
  }
  
  if (protocol < 5)
    {
      internet.SetRoutingHelper (list);
      internet.Install (adhocNodes);
    }
  else if (protocol == 5)
    {
      internet.Install (adhocNodes);
      dsrMain.Install (dsr, adhocNodes);
    }
  
  if (this->nHoles != 0 && this->protocol != 2) {
   switch (this->protocol) {
    case 1:
      std::cout << "No Blackhole mode for AODV" << std::endl;
      exit(0);
      break;
    case 2:
      
      break;
    case 3:
      std::cout << "No Blackhole mode for DSDV" << std::endl;
      exit(0);
      break;
    case 4:
      std::cout << "No Blackhole mode for OLSR" << std::endl;
      exit(0);
      break;
    case 5:
      std::cout << "No Blackhole mode for DSR" << std::endl;
      exit(0);
      break;
      
    default:
      NS_FATAL_ERROR ("No such protocol supported!");
      break;
  }
  }
  
  
  
  Ipv4AddressHelper addressAdhoc;
  addressAdhoc.SetBase("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer adhocInterfaces;
  adhocInterfaces = addressAdhoc.Assign (adhocDevices);
  
  // Install the fuzzy system on the nodes
  std::string fis_file;
  fis_file = "../src/anthocnet/fis/sniffer_analysis.fis";
    
  
  Ptr<AntHocNetFis> fis = CreateObject<AntHocNetFis>();
  fis->SetAttribute("FisFile", StringValue(fis_file));
  
  fis->Init();
  
  Ptr<AntHocNetConfig> conf = CreateObject<AntHocNetConfig>();
  conf->SetAttribute("Fis", PointerValue(fis));
  conf->SetAttribute("FuzzyMode", BooleanValue(this->use_fuzzy));
  for (uint32_t i = 0; i < this->nWifis - this->nHoles; i++) {
    std::stringstream conf_path;
    conf_path << "/NodeList/" 
      << i << "/$ns3::ahn::RoutingProtocol/Config";
    
    Config::Set(conf_path.str(), PointerValue(conf));
  }
  
  // Install blackhole mode
  for (uint32_t i = this->nWifis - this->nHoles; i < this->nWifis; i++) {
    
    Ptr<AntHocNetConfig> conf = CreateObject<AntHocNetConfig>();
    conf->SetAttribute("BlackholeMode", BooleanValue(true));
    conf->SetAttribute("Fis", PointerValue(fis));
    conf->SetAttribute("FuzzyMode", BooleanValue(this->use_fuzzy));
    
    std::stringstream conf_path;
    conf_path << "/NodeList/" 
      << i << "/$ns3::ahn::RoutingProtocol/Config";
    
    Config::Set(conf_path.str(), PointerValue(conf));
  }
  
  // Set up the application
  this->db = Create<SimDatabase>();
  
  // Set the default for the SimApllication
  Config::SetDefault("ns3::ahn::SimApplication::PacketSize", 
                     UintegerValue(this->packetSize));
  Config::SetDefault("ns3::ahn::SimApplication::PacketRate", 
                     UintegerValue(this->packetRate));
  
  Config::SetDefault("ns3::ahn::SimApplication::Database", PointerValue(this->db));
  
  
  SimHelper apphelper("Helper");
  
  // Install application in recevier mode
  apphelper.SetAttribute("SendMode", BooleanValue(false));
  for (uint32_t i = 0; i < this->nReceiver; i++) {
    
    
    apphelper.SetAttribute("Local",
                  AddressValue(
                    InetSocketAddress(adhocInterfaces.GetAddress(i))));
    
    apphelper.SetAttribute("Remote",
                  AddressValue(
                    InetSocketAddress(
                      adhocInterfaces.GetAddress((i % this->nSender) + this->nReceiver))));
    
    Time start_time = Seconds(
      random->GetValue(this->appStartBegin, appStartEnd));
    std::cout << "App starts at " << start_time.GetSeconds() << std::endl;
    
    apphelper.SetAttribute("StartTime", TimeValue(Seconds(0)));
    apphelper.SetAttribute("StopTime", TimeValue(this->total_time));
    apphelper.SetAttribute("SendStartTime", TimeValue(start_time));
    
    apphelper.Install(adhocNodes.Get(i));
    
  }
  
  // Intall application in sender mode
  apphelper.SetAttribute("SendMode", BooleanValue(true));
  for (uint32_t i = this->nReceiver;
       i < this->nReceiver + this->nSender; i++) {
    
    apphelper.SetAttribute("Local",
                  AddressValue(
                    InetSocketAddress(adhocInterfaces.GetAddress(i))));
    
    apphelper.SetAttribute("Remote",
                  AddressValue(
                    InetSocketAddress(
                      adhocInterfaces.GetAddress(i % this->nReceiver))));
  
    Time start_time = Seconds(
      random->GetValue(this->appStartBegin, appStartEnd));
    std::cout << "App starts at " << start_time.GetSeconds() << std::endl;
    
    apphelper.SetAttribute("StartTime", TimeValue(Seconds(0)));
    apphelper.SetAttribute("StopTime", TimeValue(this->total_time));
    apphelper.SetAttribute("SendStartTime", TimeValue(start_time));
    
    apphelper.Install(adhocNodes.Get(i));
    
    
  }
  
  streamIndex += apphelper.AssignStreams(adhocNodes, streamIndex);
  
  
  // Connect the tracers
  std::string IpTxPath = "/NodeList/*/$ns3::Ipv4L3Protocol/Tx";
  Config::ConnectWithoutContext (IpTxPath,
    MakeCallback(&RoutingExperiment::IpTxTracer, this));
  
  std::string IpRxPath = "/NodeList/*/$ns3::Ipv4L3Protocol/Rx";
  Config::ConnectWithoutContext (IpRxPath, 
    MakeCallback(&RoutingExperiment::IpRxTracer, this));
  
  this->data_packets = 0;
  this->data_bytes = 0;
  this->control_packets = 0;
  this->control_bytes = 0;
  
  // Start the net animator
  AnimationInterface anim (tr_name + "_animation.xml");
  
  anim.EnablePacketMetadata();
  anim.SetMaxPktsPerTraceFile(1000000000);
  anim.EnableIpv4RouteTracking(tr_name + "_route.xml", Seconds(0), 
                              Seconds(this->total_time), MilliSeconds(100));
  
  anim.SkipPacketTracing();

   // Generate ascii trace files 
    AsciiTraceHelper ascii;
    Ptr<OutputStreamWrapper> osw = ascii.CreateFileStream ((tr_name + ".tr").c_str());
    wifiPhy.EnableAsciiAll (osw);
    AsciiTraceHelper ascii1;
    MobilityHelper::EnableAsciiAll (ascii1.CreateFileStream (tr_name + ".mob")); 
  
  if (this->generate_pcap) {
    
    // phy level pcap
    //wifiPhy.EnablePcap((tr_name + ".pcap"), adhocNodes);
    
    // IP level pcap
    internet.EnablePcapIpv4((tr_name + ".pcap"), adhocNodes);
  }

  Ptr<FlowMonitor> flowmon;
  FlowMonitorHelper flowmonHelper;
    
  if ( this-> generate_flowmon && this-> protocol == 5) 
      {
      
    	std::cout << "DSR is not supported by Flowmonitor" << std::endl;
	exit(0);
      }
  else
      {
      	if(this-> generate_flowmon)
	  {
		flowmon= flowmonHelper.InstallAll();
	  }
      }
  
  
  // Schedule initial events
  Simulator::Schedule(Seconds(1), &RoutingExperiment::ProgressUpdate, this);
  
  Simulator::Stop(this->total_time);
  Simulator::Run ();
  
  flowmon->CheckForLostPackets ();
  
  Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier> (flowmonHelper.GetClassifier ());
  
  //AnalyzeResults(flowmon, total_time, nWifis);
  GenerateDetailedResults(classifier, flowmon);
  GenerateEnergyReport(deviceModels);
  
  //flowmon->SerializeToXmlFile("flow-monitor-results.xml", true, true);
  flowmon->SerializeToXmlFile("detailed-results-routing.xml", true, true);
  
  Simulator::Destroy ();
  
if (this-> generate_flowmon) {
    
	flowmon->SerializeToXmlFile ((tr_name + ".flowmon").c_str(), true, true);
  }


  // Get the result of the simulation and put them into graphs
  this->result = this->db->Evaluate(this->output_granularity);
  
  this->GenGnuplot(result.droprate, tr_name, "Droprate", 
                 "droprate", "Time [s]", "Droprate[%]", 
                this->output_granularity);
  
  this->GenGnuplot(result.end_to_end_delay, tr_name, "End-To-End Delay", 
                 "delay", "Time [s]", "End-To-End Delay[ms]", 
                 this->output_granularity);
  
  this->GenGnuplot(result.average_delay_jitter, tr_name, "Delay jitter", 
                 "delay-jitter", "Time [s]", "Jitter [ms]", 
                this->output_granularity);
  
  std::ofstream packet_log(tr_name + "_packets.log");
  this->db->Print(packet_log);
  
  std::ofstream summary(tr_name + "_summary.txt");
  //this->PrintSummary(summary);
  
}



void RoutingExperiment::GenGnuplot (std::list<double>& values, 
                                    std::string tr_name,
                                    std::string title,
                                    std::string file_ext,
                                    std::string legendX,
                                    std::string legendY,
                                    double gran
                                   ) const
{
  
  Time t = Seconds(0);
  
  Gnuplot plot (tr_name + "_" + file_ext  + ".eps");
  plot.SetTitle(title);
  plot.SetTerminal("eps");
  plot.SetLegend(legendX, legendY);
  
  Gnuplot2dDataset ds;
  ds.SetTitle (title);
  ds.SetStyle(Gnuplot2dDataset::LINES);
  
  for (auto it = values.begin(); it != values.end(); ++it) {
    
    ds.Add(t.GetSeconds(), *it);
    t += Seconds(gran);
  }
        
  plot.AddDataset(ds);
  
  std::ofstream f (tr_name + "_" + file_ext + ".plt");
  plot.GenerateOutput(f);
  
  popen( 
    ("gnuplot -c " + (tr_name + "_" + file_ext + ".plt")).c_str(), "r");
}



int main (int argc, char* argv[]) {
  RoutingExperiment experiment;
  
  timeval start;
  gettimeofday(&start, NULL);
  
  time_t tim = time(0);
  struct tm* now = localtime(&tim);
  
  // Set up the experiment
  experiment.CommandSetup(argc, argv);
  
  // Create Folders
  std::stringstream dirss;
  dirss << "anthocnet_sim_" << (now->tm_year + 1900) << "-"
    << (now->tm_mon + 1) << "-" << (now->tm_mday) << "-"
    << (now->tm_hour) << "-" << (now->tm_min) << "-"
    << (now->tm_sec);
  
  std::string dir_string = dirss.str();
  
  if (mkdir(dir_string.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) == -1) {
    std::cerr << "Could no create directory to store the results. Aborting" << std::endl;
    return -1;
  }
  
  if (chdir(dir_string.c_str()) == -1) {
    std::cerr << "Could not cd into the directory to store results. Aborting" << std::endl;
    return -1;
  }
  
  std::cout << dir_string << std::endl;
  
  std::ofstream option_file("options.txt");
  experiment.PrintOptions(option_file);
  
#define NUM_ITERATIONS 1
  
  sim_results_t result[NUM_ITERATIONS];
  
  for (uint32_t iteration = 0; iteration < NUM_ITERATIONS; iteration++) {
    
   

    experiment.Run(iteration);
    
    experiment.GetResults(result[iteration]);
    
    std::stringstream output_name;
    output_name << "experiment_" << iteration << ".txt";
    std::ofstream output_file (output_name.str());
    experiment.PrintResults(result[iteration], output_file);



  }
  

  
  
  sim_results_t end_result;
  end_result.pdr = 0;
  end_result.delay = 0;
  end_result.delay_jitter = 0;
  end_result.packet_overhead = 0;
  end_result.byte_overhead = 0;

  for (uint32_t iteration = 0; iteration < NUM_ITERATIONS; iteration++) {
    


	  //std::cout << end_result.pdr << std::endl;
	  //std::cout << end_result.delay << std::endl;
	  //std::cout << end_result.delay_jitter << std::endl;
	  //std::cout << end_result.packet_overhead << std::endl;
	  //std::cout << end_result.byte_overhead << std::endl;

    end_result.pdr += result[iteration].pdr;
    end_result.delay += result[iteration].delay;
    end_result.delay_jitter += result[iteration].delay_jitter;
    end_result.packet_overhead += result[iteration].packet_overhead;
    end_result.byte_overhead += result[iteration].byte_overhead;


    
  }
  
  end_result.pdr /= NUM_ITERATIONS;
  end_result.delay /= NUM_ITERATIONS;
  end_result.delay_jitter /= NUM_ITERATIONS;
  end_result.packet_overhead /= NUM_ITERATIONS;
  end_result.byte_overhead /= NUM_ITERATIONS;


  //std::cout << end_result.pdr << std::endl;
  //std::cout << end_result.delay << std::endl;
  //std::cout << end_result.delay_jitter << std::endl;
  //std::cout << end_result.packet_overhead << std::endl;
  //std::cout << end_result.byte_overhead << std::endl;
  
  std::ofstream output_file ("summary.txt");
  experiment.PrintResults(end_result, output_file);
  
  timeval stop;
  gettimeofday(&stop, NULL);
  
  int secs(stop.tv_sec - start.tv_sec);
  int usecs(stop.tv_usec - start.tv_usec);

  if(usecs < 0)
  {
      --secs;
      usecs += 1000000;
  }
  
  int total_time = static_cast<int>(secs * 1000 + usecs / 1000.0 + 0.5);
  std::cout << "Time: " << total_time << " milliseconds" << std::endl;
  
}
