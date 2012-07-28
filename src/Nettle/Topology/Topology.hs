-- | This module implements a data structure that can be
-- used to maintain information about the topology of an OpenFlow 
-- network. It maintains a graph whose nodes are switches and whose edges are links connect
-- switches and attaching to switches at particular ports.
module Nettle.Topology.Topology (
  LinkID
  , Topology
  , Weight
    -- * Construction
  , empty
  , addLink
  , adjustLinkWeight
  , deleteLink
  , addSwitch
  , deleteSwitch
  , addEdgePort
  , addEdgePorts
  -- * Query
  , lookupLink
  , links
  , lGraph
  , edgePorts
    -- * Shortest paths
  , ShortestPathMatrix
  , shortestPathMatrix
  , pathBetween
    -- * Utilities to create topologies
  , completeTopology
  , makeTopology
  ) where

import Nettle.Topology.LabelledGraph hiding (empty)
import qualified Nettle.Topology.LabelledGraph as LG
import Nettle.Topology.FloydWarshall
import Nettle.Topology.ExtendedDouble
import Data.Array.IArray hiding ((!))
import qualified Data.Set as Set
import Data.Set (Set)
import qualified Data.Map as Map
import Data.Map (Map, (!))
import Data.List (minimumBy, sort)
import Nettle.OpenFlow

type LinkID   = ((SwitchID,PortID), (SwitchID, PortID))

data Topology = Topology { lGraph     :: LabelledGraph SwitchID LinkID 
                         , edgePorts  :: Set (SwitchID, PortID) 
                         }

links :: Topology -> [LinkID]
links topo = map fst $ edges $ lGraph topo

data ShortestPathMatrix = 
  ShortestPathMatrix { matrix :: Array (Int, Int) (ExtendedDouble, Maybe (Int, LinkID))
                     , num2switch :: Map Int SwitchID
                     , switch2num :: Map SwitchID Int
                     } 

shortestPathMatrix :: Topology -> ShortestPathMatrix
shortestPathMatrix topology = 
  ShortestPathMatrix { matrix     = floydWarshall (array ((1,1), (r,r)) assocs)
                     , num2switch = Map.fromList numberedNodes
                     , switch2num = Map.fromList (map twist numberedNodes)}
  where r = numberOfNodes $ lGraph topology
        assocs = [ ((m,n),
                    if m==n 
                    then (Finite 0, Nothing) 
                    else case edgesFromTo u v (lGraph topology) of 
                      []    -> (Infinity, Nothing)
                      links -> let (l,w) = minimumBy (\x y -> compare (snd x) (snd y)) links 
                               in (Finite w, Just (m, l)) 
                    )
                 | (m,u) <- numberedNodes, (n,v) <- numberedNodes
                 ]
        numberedNodes = zip [1..] (nodes (lGraph topology))
        twist (a,b) = (b,a)
        
pathBetween :: ShortestPathMatrix -> SwitchID -> SwitchID -> Maybe [LinkID]
pathBetween spm source dest 
  = fmap (map (\(n,link) -> link)) $
    shortestPath (matrix spm) (switch2num spm ! source, switch2num spm ! dest)
        
lookupLink :: Topology -> SwitchID -> PortID -> (LinkID, Weight)
lookupLink topo sid pid 
  = let [lw] = filter p (edges $ lGraph topo)
    in lw
  where p (((x,y),(z,u)), _) = (x==sid && y==pid) || (z==sid && u==pid)

adjustLinkWeight :: LinkID -> (Weight -> Weight) -> Topology -> Topology
adjustLinkWeight linkid f topo
  = topo { lGraph = adjustEdgeWeight linkid f (lGraph topo) }

-- ensure invariant that no two links have same (switch,port) pairs.
addLink :: LinkID -> Weight -> Topology -> Topology
addLink e@((u,p),(v,q)) w topo
  = topo { lGraph = addEdge e (u,v) w (lGraph topo) }

deleteLink :: LinkID -> Topology -> Topology
deleteLink lid  topo 
  = topo { lGraph = deleteEdge lid (lGraph topo ) }

addSwitch :: SwitchID -> Topology -> Topology
addSwitch sid topo
  = topo { lGraph = addNode sid (lGraph topo) }

deleteSwitch :: SwitchID -> Topology -> Topology
deleteSwitch sid topo 
  = topo { lGraph =  deleteNode sid (lGraph topo) }

empty :: Topology
empty = Topology { lGraph = LG.empty, edgePorts = Set.empty }

addEdgePort :: SwitchID -> PortID -> Topology -> Topology 
addEdgePort sid pid topo 
  = topo { edgePorts = Set.insert (sid,pid) (edgePorts topo) }

addEdgePorts :: [(SwitchID, PortID)] -> Topology -> Topology
addEdgePorts sps topo 
  = topo { edgePorts = foldr Set.insert (edgePorts topo) sps } 

-- builds complete graph of n switches with the high ports (ports numbered n+1 or higher) are edge ports, with one directed edge per pair of switches.
completeTopology :: Int -> Int -> Weight -> Topology
completeTopology n portsPerSwitch weight
  = foldr f topo0 links 
  where links = concat [ [ ((s, d-1), (d,s)), ((d,s),(s,d-1)) ] | s <- [1..n], d <- [s+1..n]]
        eps   = [ (fromIntegral s, fromIntegral p) | s <- [1..n], p <- [n..portsPerSwitch]]
        f ((x,y),(z,u)) = addLink ((fromIntegral x, fromIntegral y), (fromIntegral z, fromIntegral u)) weight
        topo0 = addEdgePorts eps empty
                                           
makeTopology :: Int -> Int -> [(Int,Int,Weight)] -> Topology
makeTopology n numEdgePorts edges 
  = foldr f topo0 links
  where topo0 = addEdgePorts eps empty 
        eps   = [ (fromIntegral s, fromIntegral (nextPort + p)) 
                | s <- [1..n], 
                  let nextPort = dict ! s, 
                  p <- [0..(numEdgePorts-1)] 
                ]
        f ((x,y),(z,u),weight) = addLink ((fromIntegral x, fromIntegral y), 
                                          (fromIntegral z, fromIntegral u)) weight
        (dict, links) = 
          foldl step base (sort edges)
          where step (dict,edges) (u,v,weight) =
                  let pu     = dict ! u
                      pv     = dict ! v
                      dict'  = Map.adjust (+1) u (Map.adjust (+1) v dict)
                      edges' = ((u,pu),(v,pv),weight) : ((v,pv),(u,pu),weight) : edges
                  in (dict', edges')
                base   = (dict0, edges0)                      
                dict0  = Map.fromList [(u,1) | u <- [1..n]]
                edges0 = []