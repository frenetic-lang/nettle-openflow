module Nettle.IPv4.IPAddress where

import Data.Word
import Data.Bits 
import Data.Binary.Put
import Data.Binary.Get
import Data.Binary
import Text.ParserCombinators.Parsec
import Data.Maybe
import Text.Printf
import Data.Generics

newtype IPAddress = IPAddress { ipAddressToWord32 :: Word32 }
  deriving (Read, Eq, Ord, Data, Typeable)

type PrefixLength    = Word8

data IPAddressPrefix 
  = IPAddressPrefix IPAddress PrefixLength
  deriving (Eq, Ord, Read, Data, Typeable)
                     

instance Show IPAddress where
  show addr = printf "%03d.%03d.%03d.%03d" b3 b2 b1 b0
    where (b3, b2, b1, b0) = addressToOctets addr

instance Show IPAddressPrefix where
  show (IPAddressPrefix addr pf) =
    if pf == 32 then
      show addr
    else if pf >= 24 then
      take 11 (show addr) ++ "/" ++ show pf
    else if pf >= 16 then
      take 7 (show addr) ++ "/" ++ show pf
    else
      take 3 (show addr) ++ "/" ++ show pf

ipAddress :: Word8 -> Word8 -> Word8 -> Word8 -> IPAddress
ipAddress b1 b2 b3 b4 = 
    IPAddress $ foldl (\a b -> shift a 8 + fromIntegral b) (0 :: Word32) [b1,b2,b3,b4]

instance Binary IPAddress where
  get = do
    w <- getWord32be
    return (IPAddress w)
  put (IPAddress w) = do
    putWord32be w

(//) :: IPAddress -> PrefixLength -> IPAddressPrefix
(IPAddress a) // len = a' `seq` IPAddressPrefix (IPAddress a') len
    where a'   = a .&. mask
          mask = complement (2^(32 - fromIntegral len) - 1)

addressPart :: IPAddressPrefix -> IPAddress
addressPart (IPAddressPrefix (IPAddress a) l) = IPAddress a
{-# INLINE addressPart #-}
          
prefixLength :: IPAddressPrefix -> PrefixLength
prefixLength (IPAddressPrefix _ l) = l
{-# INLINE prefixLength #-}

maxPrefixLen :: Word8
maxPrefixLen = 32

prefixIsExact :: IPAddressPrefix -> Bool
prefixIsExact (IPAddressPrefix _ l) = l==maxPrefixLen

defaultIPPrefix = ipAddress 0 0 0 0 // 0

addressToOctets :: IPAddress -> (Word8, Word8, Word8, Word8)
addressToOctets (IPAddress addr) = (b1,b2,b3,b4)
    where b4 = fromIntegral $ addr .&. (2^8 - 1)
          b3 = fromIntegral $ shiftR (addr .&. (2^16 - 1)) 8
          b2 = fromIntegral $ shiftR (addr .&. (2^24 - 1)) 16
          b1 = fromIntegral $ shiftR (addr .&. (2^32 - 1)) 24

prefixPlus :: IPAddressPrefix -> Word32 -> IPAddress
prefixPlus (IPAddressPrefix (IPAddress addr) _) x = IPAddress (addr + x)

prefixOverlaps :: IPAddressPrefix -> IPAddressPrefix -> Bool
prefixOverlaps p1@(IPAddressPrefix (IPAddress addr) len) 
               p2@(IPAddressPrefix (IPAddress addr') len') 
    | addr .&. mask == addr' .&. mask = True
    | otherwise                       = False
    where len'' = min len len'
          mask  = foldl setBit (0 :: Word32) [(32 - fromIntegral len'')..31]

elemOfPrefix :: IPAddress -> IPAddressPrefix -> Bool
elemOfPrefix addr prefix  = (addr // 32) `prefixOverlaps` prefix

intersect :: IPAddressPrefix -> IPAddressPrefix -> Maybe IPAddressPrefix
intersect p1@(IPAddressPrefix _ len1) p2@(IPAddressPrefix _ len2) 
    | p1 `prefixOverlaps` p2 = Just longerPrefix
    | otherwise              = Nothing
    where longerPrefix = if len1 < len2 then p2 else p1

intersects :: [IPAddressPrefix] -> Maybe IPAddressPrefix
intersects = foldl f (Just defaultIPPrefix)
    where f mpref pref = maybe Nothing (intersect pref) mpref

disjoint :: IPAddressPrefix -> IPAddressPrefix -> Bool
disjoint p1 p2 = not (p1 `prefixOverlaps` p2)

disjoints :: [IPAddressPrefix] -> Bool
disjoints = isNothing . intersects

isSubset :: IPAddressPrefix -> IPAddressPrefix -> Bool
isSubset p1@(IPAddressPrefix _ l) p2@(IPAddressPrefix _ l') = 
  l <= l' && (p1 `prefixOverlaps` p2)

parseIPAddress :: String -> Maybe IPAddress
parseIPAddress s = case parse ipAddressParser "" s of 
                     Right a -> Just a
                     Left _  -> Nothing

ipAddressParser :: CharParser () IPAddress
ipAddressParser = do a <- many1 digit
                     char '.'
                     b <- many1 digit
                     char '.'
                     c <- many1 digit
                     char '.'
                     d <- many1 digit
                     return $ ipAddress (read a) (read b) (read c) (read d)
