/* ez_status.c -- names for ez_status_t (see ez_status.h). */
#include "ez_status.h"

const char *ez_status_name(ez_status_t s)
{
	switch (s) {
	case EZ_OK:                 return "OK";
	case EZ_ERR_BUSY:           return "BUSY";
	case EZ_ERR_BAD_REQUEST:    return "BAD_REQUEST";
	case EZ_ERR_NO_SESSION:     return "NO_SESSION";
	case EZ_ERR_QUARANTINED:    return "QUARANTINED";
	case EZ_ERR_CAPACITY:       return "CAPACITY";
	case EZ_ERR_RANGE:          return "RANGE";
	case EZ_ERR_REPLAY:         return "REPLAY";
	case EZ_ERR_KEY_ID:         return "KEY_ID";
	case EZ_ERR_MEDIA_REMOVED:  return "MEDIA_REMOVED";
	case EZ_ERR_MEDIA:          return "MEDIA";
	case EZ_ERR_META:           return "META";
	case EZ_ERR_INTEGRITY:      return "INTEGRITY";
	case EZ_ERR_ENTROPY:        return "ENTROPY";
	case EZ_ERR_DRIVE_DISABLED: return "DRIVE_DISABLED";
	case EZ_ERR_EXISTS:         return "EXISTS";
	case EZ_ERR_NOT_FOUND:      return "NOT_FOUND";
	case EZ_ERR_ABORTED:        return "ABORTED";
	case EZ_ERR_DEVICE:         return "DEVICE";
	case EZ_ERR_UNSUPPORTED:    return "UNSUPPORTED";
	case EZ_ERR_ROLLBACK:       return "ROLLBACK";
	case EZ_ERR_FULL:           return "FULL";
	case EZ_ERR_UNRESOLVED:     return "UNRESOLVED";
	case EZ_ERR_STATE:          return "STATE";
	case EZ_ERR_KEY_PARAM:      return "KEY_PARAM";
	case EZ_PENDING:            return "PENDING";
	case EZ_ERR_KEY_DAMAGED:    return "KEY_DAMAGED";
	case EZ_ERR_UNVERIFIED:     return "UNVERIFIED";
	case EZ_ERR_PROTECTION:     return "PROTECTION";
	}
	return "UNKNOWN";
}
