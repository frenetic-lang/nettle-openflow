{-# LANGUAGE CPP #-}

module Nettle.OpenFlow.Action (
  -- * Actions
  Action (..)
  , ActionType (..)
  , PseudoPort (..)
  , MaxLenToSendController
  , VendorID
  , QueueID
  -- * Action sequences
  , ActionSequence(..)
  , sendOnPort, sendOnInPort, flood, drop, allPhysicalPorts, processNormally, sendToController, processWithTable
  , setVlanVID, setVlanPriority, stripVlanHeader, setEthSrcAddr, setEthDstAddr
  , setIPSrcAddr, setIPDstAddr
  , setIPToS
  , setTransportSrcPort
  , setTransportDstPort
  , enqueue
  , vendorAction
  ) where

import Prelude hiding (drop)
import Nettle.OpenFlow.Port
import Nettle.Ethernet.EthernetAddress
import Nettle.Ethernet.EthernetFrame
import Nettle.IPv4.IPAddress
import Nettle.IPv4.IPPacket
import Data.Word
import Data.Generics


-- |The supported switch actions are denoted with these symbols.
data ActionType = OutputToPortType    
                | SetVlanVIDType      
                | SetVlanPriorityType 
                | StripVlanHeaderType 
                | SetEthSrcAddrType   
                | SetEthDstAddrType   
                | SetIPSrcAddrType    
                | SetIPDstAddrType    
                | SetIPTypeOfServiceType        
                | SetTransportSrcPortType
                | SetTransportDstPortType
                | EnqueueType            
                | VendorActionType
                  deriving (Show,Read,Eq,Ord,Enum,Data,Typeable)

-- | Each flow table entry contains a list of actions that will
-- be executed when a packet matches the entry. 
-- Specification: @ofp_action_header@ and all @ofp_action_*@ structures.
data Action
    = SendOutPort PseudoPort        -- ^send out given port
    | SetVlanVID VLANID             -- ^set the 802.1q VLAN ID
    | SetVlanPriority VLANPriority  -- ^set the 802.1q priority
    | StripVlanHeader               -- ^strip the 802.1q header
    | SetEthSrcAddr EthernetAddress -- ^set ethernet source address
    | SetEthDstAddr EthernetAddress -- ^set ethernet destination address
    | SetIPSrcAddr IPAddress        -- ^set IP source address
    | SetIPDstAddr IPAddress        -- ^set IP destination address
    | SetIPToS IPTypeOfService      -- ^IP ToS (DSCP field)
    | SetTransportSrcPort TransportPort -- ^set TCP/UDP source port
    | SetTransportDstPort TransportPort -- ^set TCP/UDP destination port
    | Enqueue {
        enqueuePort :: PortID,       -- ^port the queue belongs to
        queueID     :: QueueID       -- ^where to enqueue the packets
      } -- ^output to queue
    | VendorAction VendorID [Word8] 
    deriving (Show,Eq)
           

-- | A @PseudoPort@ denotes the target of a forwarding
-- action. 
data PseudoPort = PhysicalPort PortID                 -- ^send out physical port with given id
                | InPort                              -- ^send packet out the input port
                | Flood                               -- ^send out all physical ports except input port and those disabled by STP
                | AllPhysicalPorts                    -- ^send out all physical ports except input port
                | ToController MaxLenToSendController -- ^send to controller
                | NormalSwitching                     -- ^process with normal L2/L3 switching
                | WithTable                           -- ^process packet with flow table
                  deriving (Show,Read, Eq)

-- | A send to controller action includes the maximum
-- number of bytes that a switch will send to the 
-- controller.
type MaxLenToSendController = Word16

type VendorID = Word32
type QueueID  = Word32
       
-- | Sequence of actions, represented as finite lists. The Monoid instance of
-- lists provides methods for denoting the do-nothing action (@mempty@) and for concatenating action sequences @mconcat@. 
type ActionSequence = [Action]

-- | send p is a packet send action.
send :: PseudoPort -> ActionSequence
send p = [SendOutPort p]

sendOnPort :: PortID -> ActionSequence
sendOnPort p = [SendOutPort $ PhysicalPort p]

sendOnInPort, flood, drop, allPhysicalPorts, processNormally :: ActionSequence
sendOnInPort = send InPort
flood = send Flood
drop  = []
allPhysicalPorts = send AllPhysicalPorts
processNormally = send NormalSwitching
processWithTable = send WithTable

sendToController :: MaxLenToSendController -> ActionSequence
sendToController maxlen = send (ToController maxlen)

setVlanVID :: VLANID -> ActionSequence
setVlanVID vlanid = [SetVlanVID vlanid]

setVlanPriority :: VLANPriority -> ActionSequence
setVlanPriority x = [SetVlanPriority x]

stripVlanHeader :: ActionSequence
stripVlanHeader = [StripVlanHeader]

setEthSrcAddr :: EthernetAddress -> ActionSequence
setEthSrcAddr addr = [SetEthSrcAddr addr]

setEthDstAddr :: EthernetAddress -> ActionSequence
setEthDstAddr addr = [SetEthDstAddr addr]

setIPSrcAddr ::  IPAddress -> ActionSequence
setIPSrcAddr addr = [SetIPSrcAddr addr]

setIPDstAddr ::  IPAddress -> ActionSequence
setIPDstAddr addr = [SetIPDstAddr addr]

#if OPENFLOW_VERSION==152 || OPENFLOW_VERSION==1
setIPToS :: IPTypeOfService -> ActionSequence
setIPToS tos = [SetIPToS tos]
#endif

setTransportSrcPort ::  TransportPort -> ActionSequence
setTransportSrcPort port = [SetTransportSrcPort port]

setTransportDstPort ::  TransportPort -> ActionSequence
setTransportDstPort port = [SetTransportDstPort port]


#if OPENFLOW_VERSION==1    
enqueue :: PortID -> QueueID -> ActionSequence
enqueue portid queueid = [Enqueue portid queueid]    

vendorAction :: VendorID -> [Word8] -> ActionSequence
vendorAction vid bytes = [VendorAction vid bytes]
#endif



