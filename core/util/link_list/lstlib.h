/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _LISTLIB_H__
#define _LISTLIB_H__

#ifdef __cplusplus
extern "C" {
#endif

/* type definitions */

typedef struct node               /* Node of a linked list. */
    {
        struct node *next;        /* Points at the next node in the list */
        struct node *previous;    /* Points at the previous node in the list */
    } NODE;


/* HIDDEN */

typedef struct            /* Header for a linked list. */
    {
        NODE node;        /* Header list node */
        int count;        /* Number of nodes in list */
        int spare;        /* 8-byte alignment */
    } LIST;

/* END_HIDDEN */

#define lst_for_each(tmp, head)  \
	for (tmp = (head)->next; tmp != (head); tmp = tmp->next)

/* function declarations */


#if defined(__STDC__) || defined(__cplusplus)

extern NODE *   lstFirst (LIST *pList);
extern NODE *   lstGet (LIST *pList);
extern NODE *   lstLast (LIST *pList);
extern NODE *   lstNStep (NODE *pNode, int nStep);
extern NODE *   lstNext (NODE *pNode);
extern NODE *   lstNth (LIST *pList, int nodenum);
extern NODE *   lstPrevious (NODE *pNode);
extern int      lstCount (LIST *pList);
extern int      lstFind (LIST *pList, NODE *pNode);
extern void     lstAdd (LIST *pList, NODE *pNode);
extern void     lstConcat (LIST *pDstList, LIST *pAddList);
extern void     lstDelete (LIST *pList, NODE *pNode);
extern void     lstExtract (LIST *pSrcList, NODE *pStartNode, NODE *pEndNode,
                            LIST *pDstList);
extern void     lstFree (LIST *pList);
extern void     lstInit (LIST *pList);
extern void     lstInsert (LIST *pList, NODE *pPrev, NODE *pNode);

#else     /* __STDC__ */

extern NODE *   lstFirst ();
extern NODE *   lstGet ();
extern NODE *   lstLast ();
extern NODE *   lstNStep ();
extern NODE *   lstNext ();
extern NODE *   lstNth ();
extern NODE *   lstPrevious ();
extern int      lstCount ();
extern int      lstFind ();
extern void     lstAdd ();
extern void     lstConcat ();
extern void     lstDelete ();
extern void     lstExtract ();
extern void     lstFree ();
extern void     lstInit ();
extern void     lstInsert ();

#endif  /* __STDC__ */

#ifdef __cplusplus
}
#endif

#endif /* _LISTLIB_H__ */
