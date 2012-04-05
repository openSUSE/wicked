
#ifndef __WICKED_MODEM_MANAGER_H__
#define __WICKED_MODEM_MANAGER_H__

typedef struct ni_modem ni_modem_t;

ni_bool_t		ni_modem_manager_init(void);

extern ni_modem_t *	ni_modem_new(void);
extern void		ni_modem_free(ni_modem_t *);

#endif /* __WICKED_MODEM_MANAGER_H__ */

