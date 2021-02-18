/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

/* sllLib.c - singly linked list subroutine library */

/*
DESCRIPTION
This subroutine library supports the creation and maintenance of a
singly linked list.  The user supplies a list head (type SL_LIST)
that will contain pointers to the first and last nodes in the list.
The nodes in the list can be any user-defined structure, but they must reserve
space for a pointer as their first element.  The forward chain is terminated
with a NULL pointer.

.ne 16
NON-EMPTY LIST:
.CS

   ---------             --------          --------
   | head--------------->| next----------->| next---------
   |       |             |      |          |      |      |
   |       |             |      |          |      |      |
   | tail------          | ...  |    ----->| ...  |      |
   |-------|  |                      |                   v
              |                      |                 -----
              |                      |                  ---
              |                      |                   -
              ------------------------

.CE
.ne 12
EMPTY LIST:
.CS

	-----------
        |  head------------------
        |         |             |
        |  tail----------       |
        |         |     v       v
        |         |   -----   -----
        -----------    ---     ---
                        -	-

.CE

INCLUDE FILE: sllLib.h
*/

/* LINTLIBRARY */

#include "common.h"
#include "sllLib.h"

/*******************************************************************************
*
* sllInit - initialize singly linked list head
*
* Initialize the specified list to an empty list.
*
* RETURNS: 0, or -1 if intialization failed.
*/

int sllInit
    (
    SL_LIST *pList     /* pointer to list head to be initialized */
    )
    {
    pList->head	 = NULL;			/* initialize list */
    pList->tail  = NULL;

    return (0);
    }

/*******************************************************************************
*
* sllTerminate - terminate singly linked list head
*
* Terminate the specified list.
*
* RETURNS: 0, or -1 if singly linked list could not be terminated.
*
* ARGSUSED
*/

int sllTerminate
    (
    SL_LIST *pList     /* pointer to list head to be initialized */
    )
    {
    return (0);
    }

/*******************************************************************************
*
* sllPutAtHead - add node to beginning of list
*
* This routine adds the specified node to the end of the specified list.
*
* SEE ALSO: sllPutAtTail()
*/

void sllPutAtHead
    (
    SL_LIST *pList,     /* pointer to list descriptor */
    SL_NODE *pNode      /* pointer to node to be added */
    )
    {
    if ((pNode->next = pList->head) == NULL)
	pList->head = pList->tail = pNode;
    else
	pList->head = pNode;
    }

/*******************************************************************************
*
* sllPutAtTail - add node to end of list
*
* This routine adds the specified node to the end of the specified singly
* linked list.
*
* SEE ALSO: sllPutAtHead()
*/

void sllPutAtTail
    (
    SL_LIST *pList,     /* pointer to list descriptor */
    SL_NODE *pNode      /* pointer to node to be added */
    )
    {
        pNode->next = NULL;

        if (pList->head == NULL)
        {
        	pList->head = pNode;
        	pList->tail = pNode;
        }
        else
        {
        	pList->tail->next = pNode;
        	pList->tail = pNode;
        }
    }

/*******************************************************************************
*
* sllGet - get (delete and return) first node from list
*
* This routine gets the first node from the specified singly linked list,
* deletes the node from the list, and returns a pointer to the node gotten.
*
* RETURNS: Pointer to the node gotten, or NULL if the list is empty.
*/

SL_NODE *sllGet
    (
    SL_LIST *pList         /* pointer to list from which to get node */
    )
    {
    SL_NODE *pNode;

    if ((pNode = pList->head) != NULL)
        {
        pList->head = pNode->next;

        if (pList->tail == pNode)
            pList->tail = NULL;
        }

    return (pNode);
    }

//#endif	/* _WRS_PORTABLE_sllLib */

/*******************************************************************************
*
* sllRemove - remove specified node in list
*
* Remove the specified node in a singly linked list.
*/

void sllRemove
    (
    SL_LIST *pList,             /* pointer to list head */
    SL_NODE *pDeleteNode,       /* pointer to node to be deleted */
    SL_NODE *pPrevNode          /* pointer to previous node or NULL if head */
    )
    {
    if (pPrevNode == NULL)
	{
	pList->head = pDeleteNode->next;
	if (pList->tail == pDeleteNode)
	    pList->tail = NULL;
	}
    else
	{
	pPrevNode->next = pDeleteNode->next;
	if (pList->tail == pDeleteNode)
	    pList->tail = pPrevNode;
	}
    }

/*******************************************************************************
*
* sllPrevious - find and return previous node in list
*
* Find and return the previous node in a singly linked list.
*/

SL_NODE *sllPrevious
    (
    SL_LIST *pList,             /* pointer to list head */
    SL_NODE *pNode              /* pointer to node to find previous node for */
    )
    {
    SL_NODE *pTmpNode = pList->head;

    if ((pTmpNode == NULL) || (pTmpNode == pNode))
	return (NULL);					/* no previous node */

    while (pTmpNode->next != NULL)
	{
	if (pTmpNode->next == pNode)
	    return (pTmpNode);

	pTmpNode = pTmpNode->next;
	}

    return (NULL);					/* node not found */
    }

/*******************************************************************************
*
* sllCount - report number of nodes in list
*
* This routine returns the number of nodes in the given list.
*
* CAVEAT
* This routine must actually traverse the list to count the nodes.
* If counting is a time critical fuction, consider using lstLib which
* maintains a count field.
*
* RETURNS: Number of nodes in specified list.
*
* SEE ALSO: lstLib.
*/

int sllCount
    (
    SL_LIST *pList      /* pointer to list head */
    )
    {
    SL_NODE *pNode = SLL_FIRST (pList);
    int count = 0;

    while (pNode != NULL)
	{
	count ++;
	pNode = SLL_NEXT (pNode);
	}

    return (count);
    }

/*******************************************************************************
*
* sllEach - call a routine for each node in a linked list
*
* This routine calls a user-supplied routine once for each node in the
* linked list.  The routine should be declared as follows:
* .CS
*  BOOL routine (pNode, arg)
*      SL_NODE *pNode;	/@ pointer to a linked list node    @/
*      long arg;	/@ arbitrary user-supplied argument @/
* .CE
* The user-supplied routine should return G_TRUE if sllEach() is to
* continue calling it with the remaining nodes, or G_FALSE if it is done and
* sllEach() can exit.
*
* RETURNS: NULL if traversed whole linked list, or pointer to DL_NODE that
*          sllEach ended with.
*/

SL_NODE * sllEach
    (
    SL_LIST * pList,		/* linked list of nodes to call routine for */
    BOOL (* routine)		/* the routine to call for each list node */
	(
	SL_NODE * pNode,	/* pointer to a linked list node */
	long arg	/* arbitrary user-supplied argument */
        ),
    long routineArg	/* arbitrary user-supplied argument */
    )
    {
    SL_NODE *pNode = SLL_FIRST (pList);
    SL_NODE *pNext;

    while (pNode != NULL)
	{
	pNext = SLL_NEXT (pNode);
	if ((* routine) (pNode, routineArg) == G_FALSE)
	    break;
	pNode = pNext;
	}

    return (pNode);			/* return node we ended with */
    }
