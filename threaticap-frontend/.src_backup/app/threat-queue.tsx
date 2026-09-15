import { useTable } from "react-table";
import {
  useThreats,
  useCommanderStore,
  useSelectedThreat,
  useTlpFilter,
  useMitreTactic,
  stores,
} from "@/lib/api/service";
import { useEffect } from "react";
import {
  Card,
  CardHeader,
  CardTitle,
  CardContent,
  CardFooter,
} from "@/components/ui/card";
import { Table, TableHeader, TableRow, TableCell, TableBody } from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import { Select, SelectItem, SelectTrigger, SelectValue, SelectContent } from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { InputIcon, SearchIcon } from "@/components/ui/icons";
 {useEffect(() => {
  // Trigger initial load
}, []);}