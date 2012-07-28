-- | Implements the Floyd-Warshall algorithm for computing all-pairs shortest paths 
-- from a weighted directed graph. 
module Nettle.Topology.FloydWarshall (
  floydWarshall
  , shortestPath
  ) where

import Data.Array.MArray
import Data.Array.IArray
import Data.Array.ST
import Control.Monad
import Data.Map (Map)
import qualified Data.Map as Map
import Nettle.Topology.ExtendedDouble


-- | The input is a matrix where the @(i,j)@ entry contains the distance of a path
-- going from node @i@ to node @j@ in the graph as well as the next hop node in the path and a value
-- (left polymorphic, of type @a@ here) representing the link (e.g. a link identifier, particularly useful if there can
-- more than one link between nodes). If the distance is |Infinity| then the next hop and link identifier should be |Nothing|. 
-- Typically, this function is applied to an array in which @(i,j)@ value contains the distance and the link ID for one link from
-- @i@ to @j@.
floydWarshall ::  Array (Int,Int) (ExtendedDouble, Maybe (Int, a)) -> Array (Int,Int) (ExtendedDouble, Maybe (Int, a))
floydWarshall input = 
  runSTArray $
  do d <- thaw input 
     forM [1..n] $ \k ->
       forM [1..n] $ \i -> 
       forM [1..n] $ \j -> 
         do (dij, predij) <- readArray d (i,j)
            (dik, predik) <- readArray d (i,k)
            (dkj, predkj) <- readArray d (k,j)
            let dikj = dik `addExtendedDouble` dkj
            when (dikj < dij) (writeArray d (i,j) (dikj, predkj))
     return d
  where (_, (n,_)) = bounds input

-- | Extracts the shortest path from the matrix computed by |floydWarshall|. The path includes the
-- the nodes and the links of the path.
shortestPath :: Array (Int, Int) (ExtendedDouble, Maybe (Int, a)) -> (Int, Int) -> Maybe [(Int,a)]
shortestPath dp (start, end) = 
  let (_, mprev) = dp ! (start, end)
  in case mprev of 
    Nothing   -> if start == end then Just [] else Nothing
    Just (prev,a) -> aux start prev [(end,a)]
  where aux start end acc 
          | start == end = Just acc
          | otherwise    = 
            let (_,mprev) = dp ! (start,end) 
            in case mprev of 
              Nothing -> Nothing
              Just (prev,a) -> aux start prev ((end,a) : acc)


path :: Array (Int, Int) (ExtendedDouble, Maybe Int) -> (Int, Int) -> Maybe [Int]
path dp (start, end) = 
  let (_, mprev) = dp ! (start, end)
  in case mprev of 
    Nothing   -> Nothing
    Just prev -> aux start prev [end]
  where aux start end acc 
          | start == end = Just acc
          | otherwise    = 
            let (_,mprev) = dp ! (start,end) 
            in case mprev of 
              Nothing -> Nothing
              Just prev -> aux start prev (end : acc)

pathMap :: Array (Int, Int) (ExtendedDouble, Maybe Int) -> Map (Int,Int) [Int]
pathMap dp 
  = Map.fromList $ [ (k, p) | (k,_) <- assocs dp, Just p <- [path dp k] ]



{-
fw :: Int -> [ExtendedDouble] -> Array (Int,Int) ExtendedDouble
fw n dists = 
  runSTArray $
  do d <- newListArray ((1,1), (n,n)) dists
     forM [1..n] $ \k ->
       forM [1..n] $ \i -> 
       forM [1..n] $ \j -> 
         do dij <- readArray d (i,j)
            dik <- readArray d (i,k)
            dkj <- readArray d (k,j)
            writeArray d (i,j) (min dij (dik `addExtendedDouble` dkj))
     return d
     
     
-- Assumes a graph on n nodes.
-- The input is a list of hop weights and predecessor values in order of (1,1), (1,2),...(1,n),(2,1),...(n,n).
fw2 :: Int -> [(ExtendedDouble, Maybe Int)] -> Array (Int,Int) (ExtendedDouble, Maybe Int)
fw2 n dists = 
  runSTArray $
  do d <- newListArray ((1,1), (n,n)) dists
     forM [1..n] $ \k ->
       forM [1..n] $ \i -> 
       forM [1..n] $ \j -> 
         do (dij, predij) <- readArray d (i,j)
            (dik, predik) <- readArray d (i,k)
            (dkj, predkj) <- readArray d (k,j)
            let dikj = dik `addExtendedDouble` dkj
            when (dikj < dij) (writeArray d (i,j) (dikj, predkj))
     return d
-}
