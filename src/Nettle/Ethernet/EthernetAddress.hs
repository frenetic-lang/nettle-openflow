module Nettle.Ethernet.EthernetAddress
  ( -- * Ethernet address
    EthernetAddress (..)
  , ethernetAddress
  , unpackEthernetAddress
  , isReservedEthernetAddress
  , broadcastAddress
  ) where

import Data.Word
import Data.Bits
import Data.Binary
import Data.Binary.Get
import Data.Binary.Put
import Numeric (showHex)
import Data.List (intersperse)
import Data.Generics

-- | An Ethernet address consists of six bytes. These six bytes are stored in
-- the lower-order bits of a 64-bit value.
newtype EthernetAddress = EthernetAddress { unpackEth64 :: Word64 }
  deriving (Data, Typeable)

instance Eq EthernetAddress where
  (EthernetAddress w1) == (EthernetAddress w2) =
    (w1 `mod` 0x01000000000000) == (w2 `mod` 0x01000000000000)

instance Ord EthernetAddress where
  compare (EthernetAddress w1) (EthernetAddress w2) =
    compare (w1 `mod` 0x01000000000000) (w2 `mod` 0x01000000000000)

instance Show EthernetAddress where
  show eth = concat $
    intersperse ":" (map (\n -> showHex n "") [w0,w1,w2,w3,w4,w5])
      where (w0,w1,w2,w3,w4,w5) = unpackEthernetAddress eth

instance Binary EthernetAddress where

  get = do
    w32 <- getWord32be
    w16 <- getWord16be
    let w64 = (fromIntegral w32 `shiftL` 16) .|. fromIntegral w16
    return (EthernetAddress w64)

  put (EthernetAddress w64) = do
    putWord32be (fromIntegral (shiftR w64 16))
    putWord16be (fromIntegral (w64 `mod` 0x010000))

ethernetAddress :: Word8 -> Word8 -> Word8 -> Word8 -> Word8 -> Word8 
                -> EthernetAddress                                
ethernetAddress w1 w2 w3 w4 w5 w6  
  = let w64 = (shiftL (fromIntegral w1) 40) .|.
              (shiftL (fromIntegral w2) 32) .|.
              (shiftL (fromIntegral w3) 24) .|.                       
              (shiftL (fromIntegral w4) 16) .|.
              (shiftL (fromIntegral w5)  8) .|.
              (fromIntegral w6)
    in EthernetAddress w64
                                
unpackEthernetAddress :: EthernetAddress
                      -> (Word8,Word8,Word8,Word8,Word8,Word8)
unpackEthernetAddress (EthernetAddress w64) = 
  let a1 = fromIntegral (shiftR w64 40)
      a2 = fromIntegral (shiftR w64 32 `mod` 0x0100)
      a3 = fromIntegral (shiftR w64 24 `mod` 0x0100)
      a4 = fromIntegral (shiftR w64 16 `mod` 0x0100)
      a5 = fromIntegral (shiftR w64 8 `mod` 0x0100)
      a6 = fromIntegral (w64 `mod` 0x0100)
  in (a1,a2,a3,a4,a5,a6)

isReservedEthernetAddress :: EthernetAddress -> Bool
isReservedEthernetAddress e = 
  let (a1, a2, a3, a4, a5, a6) = unpackEthernetAddress e in
    a1 == 0x01 && 
    a2 == 0x80 && 
    a3 == 0xc2 && 
    a4 == 0 && 
    ((a5 .&. 0xf0) == 0)

broadcastAddress :: EthernetAddress
broadcastAddress = EthernetAddress 0xffffffffffff
