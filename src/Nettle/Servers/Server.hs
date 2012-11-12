{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE StandaloneDeriving #-}

-- | Provides a simple, basic, and efficient server which provides methods
-- to listen for new switches to connect, and to receive and send OpenFlow
-- messages to switches. This server handles the initialization procedure with switches
-- and handles echo requests from switches.
module Nettle.Servers.Server
    (     
      -- * OpenFlow Server
      OpenFlowServer
      , ServerPortNumber 
      , HostName
      , startOpenFlowServer
      , acceptSwitch 
      , closeServer
        -- * Switch connection
      , SwitchHandle
      , handle2SwitchID
      , switchSockAddr
      , receiveFromSwitch
      , sendToSwitch
      , sendToSwitchWithID
      , closeSwitchHandle
        -- * Utility
      , untilNothing
    ) where


import Control.Exception
import Network.Socket hiding (recv)
import Network.Socket.ByteString.Lazy (recv, sendAll)
import qualified Data.ByteString.Lazy as S
import Data.Binary
import Data.Binary.Get
import Data.Binary.Put
import System.IO
import Nettle.OpenFlow
import Data.Word
import Foreign
import Data.Map (Map)
import qualified Data.Map as Map
import Text.Printf
import System.Log.Logger

type ServerPortNumber = Word16

-- | Abstract type containing the state of the OpenFlow server.
newtype OpenFlowServer = OpenFlowServer (Socket, IORef (Map SwitchID SwitchHandle))

-- | Starts an OpenFlow server. 
-- The server socket will be bound to a wildcard IP address if the first argument is 'Nothing' and will be bound to a particular 
-- address if the first argument is 'Just' something. The 'HostName' value can either be an IP address in dotted quad notation, 
-- like 10.1.30.127, or a host name, whose IP address will be looked up. The server port must be specified.
startOpenFlowServer :: Maybe HostName -> ServerPortNumber -> IO OpenFlowServer
startOpenFlowServer mHostName portNumber = 
  do addrinfos  <- getAddrInfo (Just (defaultHints {addrFlags = [AI_PASSIVE]})) mHostName (Just $ show portNumber)
     let serveraddr = head addrinfos
     sock <- socket (addrFamily serveraddr) Stream defaultProtocol
     setSocketOption sock ReuseAddr 1
     -- setSocketOption sock RecvBuffer (2^7 * 2^10)
     -- setSocketOption sock SendBuffer (2^7 * 2^10)
     bindSocket sock (addrAddress serveraddr)
     listen sock queueLength
     switchHandleMapRef <- newIORef Map.empty
     return (OpenFlowServer (sock, switchHandleMapRef))
    where 
      queueLength = maxListenQueue

-- | Closes the OpenFlow server.
closeServer :: OpenFlowServer -> IO ()
closeServer (OpenFlowServer (s,_)) = sClose s


-- | Abstract type managing the state of the switch connection.
data SwitchHandle = SwitchHandle !(SockAddr, Socket, ForeignPtr Word8, IORef S.ByteString, SwitchID, OpenFlowServer)

-- | Blocks until a switch connects to the server and returns the 
-- switch handle.
acceptSwitch :: OpenFlowServer -> IO (SwitchHandle, SwitchFeatures)
acceptSwitch ofps@(OpenFlowServer (s,shmr)) = 
  do (connsock, clientaddr) <- accept s
     let bufferSize = 1024 * 1024
     outBufferPtr <- mallocForeignPtrBytes bufferSize :: IO (ForeignPtr Word8)
     inBufferRef <- newIORef S.empty
     let sh = SwitchHandle (clientaddr, connsock, outBufferPtr, inBufferRef, -1, ofps)
     (sid, sfr) <- handshake sh
     return (SwitchHandle (clientaddr, connsock, outBufferPtr, inBufferRef, sid, ofps), sfr)
  where        
    handshake switch 
      = do sendToSwitch switch (0, CSHello)
           m <- receiveFromSwitch switch
           case m of 
             Nothing -> error ("switch broke connection")
             Just (xid, msg) -> 
               case msg of 
                 SCHello -> go2 switch
                 _       -> error ("received unexpected message during handshake: " ++ show (xid, msg))
    go2 switch = go2'
      where go2' = do sendToSwitch switch (0, FeaturesRequest)
                      m <- receiveFromSwitch switch
                      case m of 
                        Nothing -> error "switch broke connection during handshake"
                        Just (xid, msg) -> 
                          case msg of 
                            Features (sfr@(SwitchFeatures { switchID })) ->
                              do switchHandleMap <- readIORef shmr
                                 writeIORef shmr (Map.insert switchID switch switchHandleMap)
                                 return (switchID, sfr)
                            SCEchoRequest bytes -> 
                              do sendToSwitch switch (xid, CSEchoReply bytes) 
                                 go2'
                            _ -> 
                              do debugM "nettle" ("ignoring non feature message while waiting for features: " ++ show (xid, msg))
                                 go2'
    
     

-- | Returns the socket address of the switch connection. 
switchSockAddr :: SwitchHandle -> SockAddr
switchSockAddr (SwitchHandle (a,_,_,_,_,_)) = a
            
-- | Blocks until a message is received from the switch or the connection is closed.
-- Returns `Nothing` only if the connection is closed.
receiveFromSwitch :: SwitchHandle -> IO (Maybe (TransactionID, SCMessage))
receiveFromSwitch sh@(SwitchHandle (clientAddr, s, _, _, _, _)) 
  = do hdrbs <- recv s headerSize 
       if (headerSize /= S.length hdrbs) 
         then if S.length hdrbs == 0 
              then return Nothing 
              else error "error reading header"
         else 
           let header = runGet getHeader hdrbs in
               do let expectedBodyLen = fromIntegral (msgLength header) - headerSize
                  bodybs <- if expectedBodyLen > 0 
                            then do bodybs <- recv s expectedBodyLen 
                                    when (expectedBodyLen /= S.length bodybs) (error "error reading body")
                                    return bodybs
                            else return S.empty
                  case runGet (getSCMessageBody header) bodybs of
                    msg -> 
                      case msg of 
                        (xid, SCEchoRequest bytes) -> do sendToSwitch sh (xid, CSEchoReply bytes)
                                                         receiveFromSwitch sh
                        _ -> return (Just msg)
  where headerSize = 8        
{-# INLINE receiveFromSwitch #-}

-- | Send a message to the switch.
sendToSwitch :: SwitchHandle -> (TransactionID, CSMessage) -> IO ()       
sendToSwitch (SwitchHandle (_,s,fptr,_,_, _)) msg =
     sendAll s (runPut (put (MessageToSwitch msg)))
{-# INLINE sendToSwitch #-}    
          
sendToSwitchWithID :: OpenFlowServer -> SwitchID -> (TransactionID, CSMessage) -> IO ()                                             
sendToSwitchWithID (OpenFlowServer (_,shmr)) sid msg 
  = do switchHandleMap <- readIORef shmr 
       case Map.lookup sid switchHandleMap of
         Nothing -> printf "Tried to send message to switch: %d, but it is no longer connected.\nMessage was %s.\n" sid (show msg)
         Just sh -> sendToSwitch sh msg --this could fail.
{-# INLINE sendToSwitchWithID #-}                                        
     
-- | Close a switch connection.     
closeSwitchHandle :: SwitchHandle -> IO ()    
closeSwitchHandle (SwitchHandle (_, s,_,_,sid, OpenFlowServer (_, shmr))) = 
  do switchHandleMap <- readIORef shmr
     writeIORef shmr (Map.delete sid switchHandleMap) 
     sClose s

handle2SwitchID :: SwitchHandle -> SwitchID
handle2SwitchID (SwitchHandle (_, _, _, _, sid, _)) = sid
{-# INLINE handle2SwitchID #-}    

-- | Repeatedly perform the first action, passing its result to the second action, until
-- the result of the first action is 'Nothing', at which point the computation returns.
untilNothing :: IO (Maybe a) -> (a -> IO ()) -> IO ()
untilNothing sense act = go
  where go = do ma <- sense
                case ma of
                  Nothing -> return ()
                  Just a  -> act a >> go
                  
