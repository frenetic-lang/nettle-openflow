{-# LANGUAGE CPP #-}

module Nettle.OpenFlow.Switch ( 
  SwitchFeatures (..)
  , SwitchID
  , SwitchCapability (..)
  , maxNumberPorts
  , QueueConfigRequest (..)
  , QueueConfigReply (..)
  , QueueConfig (..)
  , QueueLength
  , QueueProperty (..)
  , QueueRate (..)
  ) where

import Data.Word
import Nettle.OpenFlow.Port
import Nettle.OpenFlow.Action

-- |The switch features record, summarizes information about a switch
data SwitchFeatures 
    = SwitchFeatures  { 
        switchID           :: SwitchID,           -- ^unique switch identifier 
        packetBufferSize   :: Integer,             -- ^maximum number of packets buffered at the switch
        numberFlowTables   :: Integer,              -- ^number of flow tables
        capabilities :: [SwitchCapability], -- ^switch's capabilities
        supportedActions   :: [ActionType],       -- ^switch's supported actions
        ports        :: [Port]              -- ^description of each port on switch
      } deriving (Show,Eq)

-- |A unique identifier for a switch, also known as DataPathID.
type SwitchID = Word64

-- | Maximum number of ports on a switch
maxNumberPorts :: PortID
maxNumberPorts = 0xff00


-- |The switch capabilities are denoted with these symbols
data SwitchCapability = HasFlowStats                               -- ^can provide flow statistics
                      | HasTableStats                              -- ^can provide table statistics
                      | HasPortStats                               -- ^can provide port statistics
                      | SpanningTree                               -- ^supports the 802.1d spanning tree protocol
                      | HasQueueStatistics                         -- ^can provide queue statistics
                      | CanMatchIPAddressesInARPPackets            -- ^match IP addresses in ARP packets
                      | CanReassembleIPFragments                   -- ^can reassemble IP fragments
                        deriving (Show,Eq,Ord,Enum)


data QueueConfigRequest = QueueConfigRequest PortID        
                        deriving (Show,Eq)

data QueueConfigReply = PortQueueConfig PortID [QueueConfig]
                      deriving (Show,Eq)
                               
data QueueConfig = QueueConfig QueueID [QueueProperty]
                 deriving (Show,Eq)

type QueueLength = Word16

data QueueProperty = MinRateQueue QueueRate 
                   deriving (Show,Eq)
data QueueRate = Disabled | Enabled Word16
               deriving (Show, Eq)