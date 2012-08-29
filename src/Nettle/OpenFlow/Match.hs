{-# LANGUAGE CPP, DisambiguateRecordFields, RecordWildCards, NamedFieldPuns #-}
{-# LANGUAGE BangPatterns #-}

module Nettle.OpenFlow.Match ( 
  Match (..)
  , matchAny
  , isExactMatch
  , getExactMatch
  , frameToExactMatch
  , frameToExactMatchNoPort
  , ofpVlanNone
  , matches
  ) where

import Nettle.Ethernet.EthernetAddress
import Nettle.Ethernet.EthernetFrame 
import Nettle.Ethernet.AddressResolutionProtocol
import Nettle.IPv4.IPAddress
import qualified Nettle.IPv4.IPPacket as IP
import Nettle.OpenFlow.Port
import Data.Maybe (isJust, catMaybes)
import Control.Monad.Error
import Data.HList 
import Data.List (intersperse)
import Data.Binary
import Data.Binary.Get
import Data.Binary.Put

-- | Each flow entry includes a match, which essentially defines packet-matching condition. 
-- Fields that are left Nothing are "wildcards".
data Match = Match { inPort                             :: !(Maybe PortID), 
                     srcEthAddress, dstEthAddress       :: !(Maybe EthernetAddress), 
                     vLANID                             :: !(Maybe VLANID), 
                     vLANPriority                       :: !(Maybe VLANPriority), 
                     ethFrameType                       :: !(Maybe EthernetTypeCode),
                     ipTypeOfService                    :: !(Maybe IP.IPTypeOfService), 
                     matchIPProtocol                    :: !(Maybe IP.IPProtocol), 
                     srcIPAddress, dstIPAddress         :: !IPAddressPrefix,
                     srcTransportPort, dstTransportPort :: !(Maybe IP.TransportPort) }
             deriving (Eq)

instance Show Match where
  show = showMatch

showMatch Match {..} = "Match {" ++ list ++ "}" where
  list = concat . intersperse ", " . catMaybes $ fields
  fields = [ case inPort of
               Nothing -> Nothing
               Just v -> Just $ "inPort = \"" ++ show v ++ "\""
           , case srcEthAddress of
               Nothing -> Nothing
               Just v -> Just $ "srcEthAddress = \"" ++ show v ++ "\""
           , case dstEthAddress of
               Nothing -> Nothing
               Just v -> Just $ "dstEthAddress = \"" ++ show v ++ "\""
           , case vLANID of
               Nothing -> Nothing
               Just v -> Just $ "vLANID = \"" ++ show v ++ "\""
           , case vLANPriority of
               Nothing -> Nothing
               Just v -> Just $ "vLANPriority = \"" ++ show v ++ "\""
           , case ethFrameType of
               Nothing -> Nothing
               Just v -> Just $ "ethFrameType = \"" ++ show v ++ "\""
           , case ipTypeOfService of
               Nothing -> Nothing
               Just v -> Just $ "ipTypeOfService = \"" ++ show v ++ "\""
           , case matchIPProtocol of
               Nothing -> Nothing
               Just v -> Just $ "matchIPProtocol = \"" ++ show v ++ "\""
           , case srcIPAddress of
               v@(IPAddressPrefix _ len) -> 
                 if len == 0 then Nothing
                             else Just $ "srcIPAddress = \"" ++ show v ++ "\""
           , case dstIPAddress of
               v@(IPAddressPrefix _ len) -> if len == 0 then Nothing
                             else Just $ "dstIPAddress = \"" ++ show v ++ "\""
           , case srcTransportPort of
               Nothing -> Nothing
               Just v -> Just $ "srcTransportPort = \"" ++ show v ++ "\""
           , case dstTransportPort of
               Nothing -> Nothing
               Just v -> Just $ "dstTransportPort = \"" ++ show v ++ "\""
           ]



-- |A match that matches every packet.
matchAny :: Match
matchAny = Match { inPort           = Nothing, 
                   srcEthAddress    = Nothing, 
                   dstEthAddress    = Nothing, 
                   vLANID           = Nothing, 
                   vLANPriority     = Nothing, 
                   ethFrameType     = Nothing, 
                   ipTypeOfService  = Nothing, 
                   matchIPProtocol  = Nothing, 
                   srcIPAddress     = defaultIPPrefix,
                   dstIPAddress     = defaultIPPrefix, 
                   srcTransportPort = Nothing, 
                   dstTransportPort = Nothing }

-- | Return True if given 'Match' represents an exact match, i.e. no
--   wildcards and the IP addresses' prefixes cover all bits.
isExactMatch :: Match -> Bool
isExactMatch (Match {..}) =
    (isJust inPort) &&
    (isJust srcEthAddress) &&
    (isJust dstEthAddress) &&
    (isJust vLANID) &&
    (isJust vLANPriority) &&
    (isJust ethFrameType) &&
    (isJust ipTypeOfService) &&
    (isJust matchIPProtocol) &&
    (prefixIsExact srcIPAddress) &&
    (prefixIsExact dstIPAddress) &&
    (isJust srcTransportPort) &&
    (isJust dstTransportPort)

ofpVlanNone         = 0xffff


frameToExactMatch :: PortID -> EthernetFrame -> Match
frameToExactMatch inPort frame = foldEthernetFrame frameToMatch frame
  where  m0 = matchAny { inPort = Just inPort }
         frameToMatch hdr body = 
           let m1 = addEthHeaders m0 hdr
           in foldEthernetBody (addIPHeaders m1) (addARPHeaders m1) (const m1) body  

frameToExactMatchNoPort :: EthernetFrame -> Match
frameToExactMatchNoPort frame = foldEthernetFrame frameToMatch frame
  where  frameToMatch hdr body = 
           let m1 = addEthHeaders matchAny hdr
           in foldEthernetBody (addIPHeaders m1) (addARPHeaders m1) (const m1) body  



addEthHeaders ::  Match -> EthernetHeader -> Match 
addEthHeaders m0 (EthernetHeader {..}) = 
  m0 { srcEthAddress = Just sourceMACAddress
     , dstEthAddress = Just destMACAddress
     , ethFrameType  = Just typeCode
     , vLANID        = Just (fromIntegral ofpVlanNone)
     , vLANPriority  = Just 0
     }
addEthHeaders m0 (Ethernet8021Q {..}) =
  m0 { srcEthAddress = Just sourceMACAddress
     , dstEthAddress = Just destMACAddress
     , vLANID        = Just vlanId
     , ethFrameType  = Just typeCode
     , vLANPriority  = Just priorityCodePoint
     }


addIPHeaders ::  Match -> IP.IPPacket -> Match 
addIPHeaders m1 pkt = IP.foldIPPacket g pkt
  where g iphdr ipBdy = IP.foldIPBody f' f' h' (const m2) ipBdy
           where  m2 = m1 { matchIPProtocol  = Just (IP.ipProtocol iphdr)
                          , srcIPAddress     = IP.ipSrcAddress iphdr // 32 
                          , dstIPAddress     = IP.ipDstAddress iphdr // 32 
                          , ipTypeOfService  = Just (IP.dscp iphdr) 
                          }
                  f' (src,dst) = m2 { srcTransportPort = Just src,      
                                      dstTransportPort = Just dst  } 
                  h' (icmpType,icmpCode) = m2 { srcTransportPort = Just (fromIntegral icmpType),      
                                                dstTransportPort = Just 0  } 


addARPHeaders :: Match -> ARPPacket -> Match
addARPHeaders m (ARPQuery (ARPQueryPacket {..})) = 
      m { matchIPProtocol   = Just 1 
        , srcIPAddress = querySenderIPAddress // 32
        , dstIPAddress = queryTargetIPAddress // 32 
        }
addARPHeaders m (ARPReply (ARPReplyPacket {..})) =
      m { matchIPProtocol = Just 2 
        , srcIPAddress = replySenderIPAddress // 32
        , dstIPAddress = replyTargetIPAddress // 32 
        }


-- | Utility function to get an exact match corresponding to 
-- a packet (as given by a byte sequence).
getExactMatch :: PortID -> Get Match
getExactMatch inPort = do
  frame <- get
  return (frameToExactMatch inPort frame)


-- | Models the match semantics of an OpenFlow switch.
matches :: (PortID, EthernetFrame) -> Match -> Bool
matches (inPort, frame) (m@Match { inPort=inPort', ipTypeOfService=ipTypeOfService',..}) = 
    and [maybe True matchesInPort           inPort', 
         maybe True matchesSrcEthAddress    srcEthAddress,
         maybe True matchesDstEthAddress    dstEthAddress, 
         maybe True matchesVLANID           vLANID, 
         maybe True matchesVLANPriority     vLANPriority,
         maybe True matchesEthFrameType     ethFrameType, 
         maybe True matchesIPProtocol       matchIPProtocol, 
         maybe True matchesIPToS            ipTypeOfService',
         matchesIPSourcePrefix srcIPAddress,
         matchesIPDestPrefix dstIPAddress,
         maybe True matchesSrcTransportPort srcTransportPort, 
         maybe True matchesDstTransportPort dstTransportPort ]
        where
          ethHeader = hOccurs frame
          matchesInPort p = p == inPort
          matchesSrcEthAddress a = sourceMACAddress ethHeader == a 
          matchesDstEthAddress a = destMACAddress ethHeader == a 
          matchesVLANID a = 
              case ethHeader of 
                EthernetHeader {} -> True
                Ethernet8021Q {..}-> a == vlanId
          matchesVLANPriority a = 
              case ethHeader of 
                EthernetHeader {}  -> True
                Ethernet8021Q {..} -> a == priorityCodePoint
          matchesEthFrameType  t = t == typeCode ethHeader
          matchesIPProtocol protCode = 
              case eth_ip_packet frame of 
                Just pkt -> IP.ipProtocol (hOccurs pkt) == protCode
                _        -> True
          matchesIPToS tos =
                case eth_ip_packet frame of 
                  Just pkt -> tos == IP.dscp (hOccurs pkt)
                  _        -> True
          matchesIPSourcePrefix prefix = 
              case eth_ip_packet frame of 
                Just pkt -> IP.ipSrcAddress (hOccurs pkt) `elemOfPrefix` prefix
                Nothing  -> True
          matchesIPDestPrefix prefix = 
              case eth_ip_packet frame of 
                Just pkt -> IP.ipSrcAddress (hOccurs pkt) `elemOfPrefix` prefix
                Nothing  -> True
          matchesSrcTransportPort sp = 
                case eth_ip_packet frame of
                  Just pkt -> 
                    case hOccurs pkt of
                      IP.TCPInIP (srcPort, _) -> srcPort == sp
                      IP.UDPInIP (srcPort, _) body -> srcPort == sp
                      _ -> True
                  Nothing -> True
          matchesDstTransportPort dp = 
                case eth_ip_packet frame of
                  Just ipPacket ->
                    case hOccurs ipPacket of 
                      IP.TCPInIP (_, dstPort) -> dstPort == dp
                      IP.UDPInIP (_, dstPort) body -> dstPort == dp
                      _                       -> True
                  Nothing -> True
