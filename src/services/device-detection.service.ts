import { Injectable } from '@nestjs/common';
import { UAParser } from 'ua-parser-js';
import * as crypto from 'crypto';
import { DeviceInfo } from '../interfaces/session.interface';

/**
 * Service for detecting and tracking user devices
 * Used for multi-session management and security
 */
@Injectable()
export class DeviceDetectionService {
  /**
   * Extract device information from request
   * @param userAgent - User agent string from request
   * @param ip - IP address from request
   * @returns Device information object
   */
  extractDeviceInfo(userAgent: string, ip: string): DeviceInfo {
    const parser = new UAParser(userAgent);
    const result = parser.getResult();

    // Determine device type
    const deviceType = this.determineDeviceType(result);

    // Create device fingerprint
    const fingerprint = this.createDeviceFingerprint(userAgent, ip, result);

    return {
      userAgent,
      ip,
      deviceType,
      browser: result.browser.name || 'unknown',
      os: result.os.name || 'unknown',
      fingerprint,
      isTrusted: false, // Will be set based on previous sessions
    };
  }

  /**
   * Determine device type from parsed user agent
   * @param result - Parsed user agent result
   * @returns Device type
   */
  private determineDeviceType(
    result: UAParser.IResult,
  ): 'mobile' | 'desktop' | 'tablet' | 'unknown' {
    if (result.device.type === 'mobile') return 'mobile';
    if (result.device.type === 'tablet') return 'tablet';
    if (result.device.type === 'console') return 'desktop';

    // If no device type is detected, use OS to guess
    const os = result.os.name?.toLowerCase();
    if (os?.includes('android') || os?.includes('ios')) return 'mobile';
    if (os?.includes('windows') || os?.includes('mac') || os?.includes('linux'))
      return 'desktop';

    return 'unknown';
  }

  /**
   * Create unique device fingerprint
   * @param userAgent - User agent string
   * @param ip - IP address
   * @param result - Parsed user agent result
   * @returns Device fingerprint hash
   */
  private createDeviceFingerprint(
    userAgent: string,
    ip: string,
    result: UAParser.IResult,
  ): string {
    const components = [
      result.browser.name || '',
      result.browser.version || '',
      result.os.name || '',
      result.os.version || '',
      result.device.vendor || '',
      result.device.model || '',
      ip,
    ];

    // Create hash from components
    const fingerprint = crypto
      .createHash('sha256')
      .update(components.join('|'))
      .digest('hex');

    return fingerprint.substring(0, 16); // Use first 16 characters
  }

  /**
   * Check if device is trusted based on previous sessions
   * @param fingerprint - Device fingerprint
   * @param userId - User ID
   * @returns Whether device is trusted
   */
  async isDeviceTrusted(fingerprint: string, userId: number): Promise<boolean> {
    // Device trust checking - currently returns false for security
    // Can be enhanced to check against a trusted devices database
    // Example: const trustedDevice = await this.deviceRepository.findByFingerprint(fingerprint, userId);
    // return !!trustedDevice;

    return false; // Default to not trusted for security
  }

  /**
   * Mark device as trusted
   * @param fingerprint - Device fingerprint
   * @param userId - User ID
   */
  async markDeviceAsTrusted(
    fingerprint: string,
    userId: number,
  ): Promise<void> {
    // Device trust marking - currently just logs for security
    // Can be enhanced to store in trusted devices database
    // Example: await this.deviceRepository.markAsTrusted(fingerprint, userId);
    console.log(`Device ${fingerprint} marked as trusted for user ${userId}`);
  }

  /**
   * Get device display name for UI
   * @param deviceInfo - Device information
   * @returns User-friendly device name
   */
  getDeviceDisplayName(deviceInfo: DeviceInfo): string {
    const browser = deviceInfo.browser || 'Unknown Browser';
    const os = deviceInfo.os || 'Unknown OS';
    const deviceType = deviceInfo.deviceType;

    // Create friendly device name
    switch (deviceType) {
      case 'mobile':
        return `📱 ${browser} on ${os}`;
      case 'tablet':
        return `📱 ${browser} on ${os}`;
      case 'desktop':
        return `💻 ${browser} on ${os}`;
      default:
        return `🔧 ${browser} on ${os}`;
    }
  }

  /**
   * Check if two devices are similar (same user, different sessions)
   * @param device1 - First device
   * @param device2 - Second device
   * @returns Similarity score (0-1)
   */
  calculateDeviceSimilarity(device1: DeviceInfo, device2: DeviceInfo): number {
    let score = 0;
    let factors = 0;

    // Check browser
    if (device1.browser === device2.browser) {
      score += 0.3;
    }
    factors += 0.3;

    // Check OS
    if (device1.os === device2.os) {
      score += 0.3;
    }
    factors += 0.3;

    // Check device type
    if (device1.deviceType === device2.deviceType) {
      score += 0.2;
    }
    factors += 0.2;

    // Check IP (same network)
    if (device1.ip === device2.ip) {
      score += 0.2;
    }
    factors += 0.2;

    return score / factors;
  }
}
