{-# LANGUAGE MultiParamTypeClasses, RecordWildCards, TypeOperators #-}

module Nettle.Ethernet.AddressResolutionProtocol ( 
  ARPPacket (..)
  , ARPQueryPacket(..)
  , ARPReplyPacket(..)
  , getARPPacket
  , putARPPacket
  ) where

import Nettle.Ethernet.EthernetAddress
import Nettle.IPv4.IPAddress
import Data.Binary
import Data.Binary.Put
import Data.Binary.Get
import Data.Word
import Control.Monad
import Control.Monad.Error
import Data.HList

data ARPPacket = ARPQuery ARPQueryPacket
               | ARPReply ARPReplyPacket
               deriving (Show, Eq)

data ARPQueryPacket = 
  ARPQueryPacket { querySenderEthernetAddress :: EthernetAddress
                 , querySenderIPAddress       :: IPAddress
                 , queryTargetIPAddress       :: IPAddress
                 } deriving (Show,Eq)


data ARPReplyPacket = 
  ARPReplyPacket { replySenderEthernetAddress :: EthernetAddress
                 , replySenderIPAddress       :: IPAddress
                 , replyTargetEthernetAddress :: EthernetAddress
                 , replyTargetIPAddress       :: IPAddress
                 } 
  deriving (Show, Eq)

queryOpCode, replyOpCode :: Word16
queryOpCode = 1
replyOpCode = 2


-- | Parser for ARP packets
getARPPacket :: Get (Maybe ARPPacket)
getARPPacket = do 
  htype <- getWord16be
  ptype <- getWord16be
  hlen  <- getWord8
  plen  <- getWord8
  opCode <- getWord16be
  sha <- get
  spa <- get
  tha <- get
  tpa <- get
  body <- if opCode == queryOpCode
          then return ( Just (ARPQuery (ARPQueryPacket { querySenderEthernetAddress = sha
                                                       , querySenderIPAddress       = spa
                                                       , queryTargetIPAddress       = tpa
                                                       } 
                                       )
                             )
                      )
          else if opCode == replyOpCode 
               then return (Just (ARPReply (ARPReplyPacket { replySenderEthernetAddress = sha
                                                           , replySenderIPAddress       = spa
                                                           , replyTargetEthernetAddress = tha
                                                           , replyTargetIPAddress       = tpa
                                                           } 
                                           )
                                 )
                           )
               else return Nothing
  return body



putARPPacket :: ARPPacket -> Put
putARPPacket body = 
  case body of 
    (ARPQuery (ARPQueryPacket {..})) -> 
      do 
        putWord16be ethernetHardwareType
        putWord16be ipProtocolType
        putWord8 numberOctetsInEthernetAddress
        putWord8 numberOctetsInIPAddress
        putWord16be queryOpCode
        put querySenderEthernetAddress
        put querySenderIPAddress
        put (ethernetAddress 0 0 0 0 0 0)
        put queryTargetIPAddress
        
    (ARPReply (ARPReplyPacket {..})) -> 
      do 
        putWord16be ethernetHardwareType
        putWord16be ipProtocolType
        putWord8 numberOctetsInEthernetAddress
        putWord8 numberOctetsInIPAddress
        putWord16be replyOpCode
        put replySenderEthernetAddress
        put replySenderIPAddress
        put replyTargetEthernetAddress
        put replyTargetIPAddress

ethernetHardwareType          = 1
ipProtocolType                = 0x0800
numberOctetsInEthernetAddress = 6
numberOctetsInIPAddress       = 4

