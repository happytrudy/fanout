package main

import "strings"

const tunnelTagPrefix = "fanout-"

func tunnelTag(t *Tunnel) string {
	return tunnelTagPrefix + sanitizeTag(t.snapshot().Node.HostName)
}

func sanitizeTag(name string) string {
	var out strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			out.WriteRune(r)
		default:
			out.WriteByte('-')
		}
	}
	return strings.Trim(out.String(), "-")
}

func exitLabel(t *Tunnel) string {
	state := t.snapshot()
	region := state.Node.CountryCode
	if region == "" {
		region = state.Node.Country
	}
	suffix := state.Node.HostName
	if state.ExitIP != "" {
		if i := strings.LastIndex(state.ExitIP, "."); i >= 0 {
			suffix = state.ExitIP[i+1:]
		} else {
			suffix = state.ExitIP
		}
	}
	if region == "" {
		return suffix
	}
	return region + "-" + suffix
}

func renameExitSuffix(remark, newLabel string) string {
	if remark == "" {
		return remark
	}
	parts := strings.Split(remark, "-")
	if len(parts) < 2 {
		return remark
	}
	keep := parts[:len(parts)-2]
	if len(keep) == 0 {
		return newLabel
	}
	return strings.Join(keep, "-") + "-" + newLabel
}
