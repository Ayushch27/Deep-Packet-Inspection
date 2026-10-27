package com.dpi.dpi;

import com.dpi.flow.Flow;
import com.dpi.model.PacketInfo;

/**
 * Interface for all deep packet inspection protocol detectors.
 */
public interface ProtocolDetector {
    
    /**
     * Inspects the packet and flow state to determine the application protocol.
     * 
     * @param flow The current flow state.
     * @param packet The newest packet belonging to the flow.
     * @return A DetectionResult if a protocol is identified, or null if unknown.
     */
    DetectionResult detect(Flow flow, PacketInfo packet);
}
